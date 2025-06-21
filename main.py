from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException
import yaml
from datetime import datetime, timedelta
import replicate
import json
from typing import Dict, List, Any
import threading
import time

# Add to your environment variables
import os
from dotenv import load_dotenv

load_dotenv() 

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
REPLICATE_API_TOKEN = os.getenv('REPLICATE_API_TOKEN')

# Configuration
GOOGLE_ADS_CONFIG = {
    'developer_token': os.getenv('GOOGLE_ADS_DEVELOPER_TOKEN'),
    'client_id': os.getenv('GOOGLE_ADS_CLIENT_ID'),
    'client_secret': os.getenv('GOOGLE_ADS_CLIENT_SECRET'),
    'refresh_token': os.getenv('GOOGLE_ADS_REFRESH_TOKEN'),
    'login_customer_id': os.getenv('GOOGLE_ADS_LOGIN_CUSTOMER_ID')
}

class GoogleAdsManager:
    def __init__(self):
        self.client = None
    
    def initialize_client(self, config):
        """Initialize Google Ads client with proper credentials"""
        try:
            # Validate required config fields
            required_fields = ['developer_token', 'client_id', 'client_secret', 'refresh_token']
            for field in required_fields:
                if not config.get(field):
                    print(f"Missing required field: {field}")
                    return False
            
            # Create yaml config for Google Ads client
            yaml_config = {
                'developer_token': config['developer_token'],
                'client_id': config['client_id'],
                'client_secret': config['client_secret'],
                'refresh_token': config['refresh_token'],
                'use_proto_plus': True
            }
            
            # Add login_customer_id only if provided
            if config.get('login_customer_id'):
                yaml_config['login_customer_id'] = config['login_customer_id']
            
            # Save to temporary file
            config_path = f'google-ads-{int(time.time())}.yaml'
            with open(config_path, 'w') as f:
                yaml.dump(yaml_config, f)
            
            self.client = GoogleAdsClient.load_from_storage(config_path)
            
            # Clean up temp file
            try:
                os.remove(config_path)
            except:
                pass
                
            return True
        except Exception as e:
            print(f"Error initializing client: {e}")
            return False
    
    def test_account_access(self, customer_id):
        """Test if we can access the customer account"""
        try:
            if not self.client:
                print("❌ Client not initialized")
                return False
                
            # Use a simple query to test account access
            ga_service = self.client.get_service("GoogleAdsService")
            
            query = """
                SELECT customer.id, customer.descriptive_name
                FROM customer
                LIMIT 1
            """
            
            print(f"Testing access for customer ID: {customer_id}")
            response = ga_service.search(customer_id=customer_id, query=query)
            
            # Try to get the first row
            for row in response:
                print(f"✅ Account access successful: {row.customer.descriptive_name} (ID: {row.customer.id})")
                return True
            
            # If we get here, the query returned no results but didn't error
            print(f"⚠️ Account accessible but no customer data returned")
            return True
            
        except GoogleAdsException as ex:
            print(f"❌ Account access failed: {ex.error.code().name}")
            for error in ex.failure.errors:
                print(f"Error: {error.message}")
                print(f"Error code: {error.error_code}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error during account test: {e}")
            return False
    
    def get_campaign_spend_data(self, customer_id, date_range_days=30):
        """Fetch campaign spend data for the specified date range"""
        try:
            if not self.client:
                print("❌ Client not initialized")
                return None
            
            # Test account access first
            if not self.test_account_access(customer_id):
                print("❌ Account access test failed")
                return None
            
            ga_service = self.client.get_service("GoogleAdsService")
            
            # Use a more reliable query with explicit date range
            query = f"""
                SELECT 
                    campaign.id,
                    campaign.name,
                    campaign.status,
                    metrics.cost_micros,
                    metrics.impressions,
                    metrics.clicks
                FROM campaign 
                WHERE segments.date DURING LAST_{date_range_days}_DAYS
                AND campaign.status IN ('ENABLED', 'PAUSED')
                ORDER BY campaign.name
            """
            
            print(f"Querying customer ID: {customer_id}")
            print(f"Date range: Last {date_range_days} days")
            
            response = ga_service.search(customer_id=customer_id, query=query)
            
            campaigns_data = []
            campaign_totals = {}  # To aggregate data by campaign
            
            for row in response:
                campaign_id = str(row.campaign.id)
                
                # Aggregate data by campaign (since we might get multiple rows per campaign)
                if campaign_id not in campaign_totals:
                    campaign_totals[campaign_id] = {
                        'campaign_id': campaign_id,
                        'campaign_name': row.campaign.name,
                        'campaign_status': row.campaign.status.name,
                        'cost': 0,
                        'impressions': 0,
                        'clicks': 0
                    }
                
                campaign_totals[campaign_id]['cost'] += row.metrics.cost_micros / 1_000_000
                campaign_totals[campaign_id]['impressions'] += row.metrics.impressions
                campaign_totals[campaign_id]['clicks'] += row.metrics.clicks
            
            # Convert to list format
            campaigns_data = list(campaign_totals.values())
            
            print(f"Found {len(campaigns_data)} campaigns")
            for campaign in campaigns_data:
                print(f"Campaign: {campaign['campaign_name']} - Status: {campaign['campaign_status']} - Spend: ${campaign['cost']:.2f}")
            
            return campaigns_data
        
        except GoogleAdsException as ex:
            print(f"❌ GoogleAds Request failed: {ex.error.code().name}")
            if hasattr(ex, 'request_id'):
                print(f"Request ID: {ex.request_id}")
            for error in ex.failure.errors:
                print(f"Error message: {error.message}")
                print(f"Error code: {error.error_code}")
            return None
        except Exception as e:
            print(f"❌ An unexpected error occurred: {e}")
            import traceback
            traceback.print_exc()
            return None

ads_manager = GoogleAdsManager()

class ReplicateAIAnalyst:
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.client = None
        if api_token:
            try:
                os.environ["REPLICATE_API_TOKEN"] = api_token
                import replicate
                self.client = replicate
                print("✅ Replicate client initialized")
            except Exception as e:
                print(f"❌ Failed to initialize Replicate client: {e}")
                self.client = None
    
    def get_quick_insights_async(self, campaigns_data: List[Dict], total_spend: float, 
                                total_clicks: int, total_impressions: int, callback=None):
        """Get AI insights asynchronously to avoid blocking main thread"""
        
        def run_analysis():
            try:
                result = self._generate_insights(campaigns_data, total_spend, total_clicks, total_impressions)
                if callback:
                    callback(result)
                return result
            except Exception as e:
                error_result = {
                    'success': False,
                    'error': f"AI analysis failed: {str(e)}"
                }
                if callback:
                    callback(error_result)
                return error_result
        
        # Run in background thread
        thread = threading.Thread(target=run_analysis)
        thread.daemon = True
        thread.start()
        
        return {
            'success': True,
            'status': 'processing',
            'message': 'AI analysis is being generated...'
        }
    
    def _generate_insights(self, campaigns_data: List[Dict], total_spend: float, 
                          total_clicks: int, total_impressions: int) -> Dict[str, Any]:
        """Internal method to generate insights"""
        
        if not self.client:
            return {
                'success': False,
                'error': 'Replicate API not configured'
            }
        
        try:
            # Calculate key metrics
            overall_ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0
            overall_cpc = (total_spend / total_clicks) if total_clicks > 0 else 0
            
            # Prepare summary data
            active_campaigns = len([c for c in campaigns_data if c['campaign_status'] == 'ENABLED'])
            total_campaigns = len(campaigns_data)
            
            # Find best and worst performing campaigns by CTR
            campaign_performance = []
            for campaign in campaigns_data:
                ctr = (campaign['clicks'] / campaign['impressions'] * 100) if campaign['impressions'] > 0 else 0
                campaign_performance.append({
                    'name': campaign['campaign_name'],
                    'ctr': ctr,
                    'spend': campaign['cost']
                })
            
            campaign_performance.sort(key=lambda x: x['ctr'], reverse=True)
            best_campaign = campaign_performance[0] if campaign_performance else None
            worst_campaign = campaign_performance[-1] if campaign_performance else None
            
            # Create concise prompt for 2-sentence analysis
            prompt = f"""
            As a Google Ads expert, analyze this campaign data and provide EXACTLY 2 sentences of actionable advice:

            Performance Summary:
            - Total Spend: ${total_spend:.2f}
            - Total Clicks: {total_clicks}
            - Overall CTR: {overall_ctr:.2f}%
            - Overall CPC: ${overall_cpc:.2f}
            - Active Campaigns: {active_campaigns}/{total_campaigns}
            
            Best Performer: {best_campaign['name'] if best_campaign else 'None'} (CTR: {best_campaign['ctr']:.2f}%)
            Worst Performer: {worst_campaign['name'] if worst_campaign else 'None'} (CTR: {worst_campaign['ctr']:.2f}%)
            
            Provide exactly 2 sentences with specific, actionable advice for improving campaign performance.
            """
            
            # Use Llama 2 70B model for analysis with timeout
            output = self.client.run(
                "meta/llama-2-70b-chat:02e509c789964a7ea8736978a43525956ef40397be9033abf9fd2badfe68c9e3",
                input={
                    "prompt": prompt,
                    "max_new_tokens": 200,
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "repetition_penalty": 1.15
                }
            )
            
            # Join the output if it's a generator/list
            if hasattr(output, '__iter__') and not isinstance(output, str):
                analysis_text = ''.join(output)
            else:
                analysis_text = str(output)
            
            # Clean up the response to ensure it's concise
            sentences = analysis_text.strip().split('.')
            if len(sentences) >= 2:
                final_analysis = '. '.join(sentences[:2]) + '.'
            else:
                final_analysis = analysis_text.strip()
            
            return {
                'success': True,
                'analysis': final_analysis,
                'metrics': {
                    'overall_ctr': round(overall_ctr, 2),
                    'overall_cpc': round(overall_cpc, 2),
                    'active_campaigns': active_campaigns,
                    'total_campaigns': total_campaigns,
                    'best_campaign': best_campaign,
                    'worst_campaign': worst_campaign
                }
            }
            
        except Exception as e:
            print(f"❌ AI analysis error: {e}")
            return {
                'success': False,
                'error': f"AI analysis failed: {str(e)}"
            }

# Initialize Replicate AI Analyst
replicate_analyst = ReplicateAIAnalyst(REPLICATE_API_TOKEN) if REPLICATE_API_TOKEN else None

# Store for async AI results
ai_results_store = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        config = {
            'developer_token': request.form.get('developer_token', '').strip(),
            'client_id': request.form.get('client_id', '').strip(),
            'client_secret': request.form.get('client_secret', '').strip(),
            'refresh_token': request.form.get('refresh_token', '').strip(),
            'login_customer_id': request.form.get('login_customer_id', '').strip()
        }
        
        # Validate required fields
        required_fields = ['developer_token', 'client_id', 'client_secret', 'refresh_token']
        missing_fields = [field for field in required_fields if not config[field]]
        
        if missing_fields:
            flash(f'Please fill in all required fields: {", ".join(missing_fields)}', 'error')
            return render_template('setup.html')
        
        if ads_manager.initialize_client(config):
            session['ads_configured'] = True
            flash('Google Ads API configured successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to configure Google Ads API. Please check your credentials.', 'error')
    
    return render_template('setup.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('ads_configured'):
        flash('Please configure your Google Ads API credentials first.', 'warning')
        return redirect(url_for('setup'))
    
    return render_template('dashboard.html')

@app.route('/fetch_data', methods=['POST'])
def fetch_data():
    if not session.get('ads_configured'):
        return redirect(url_for('setup'))
    
    customer_id = request.form.get('customer_id', '').strip()
    date_range = int(request.form.get('date_range', 30))
    
    if not customer_id:
        flash('Please provide a customer ID.', 'error')
        return redirect(url_for('dashboard'))
    
    # Remove any formatting from customer ID and validate
    customer_id = customer_id.replace('-', '').replace(' ', '')
    
    if not customer_id.isdigit() or len(customer_id) < 10:
        flash('Please provide a valid customer ID (10+ digits).', 'error')
        return redirect(url_for('dashboard'))
    
    print(f"🔍 Fetching data for Customer ID: {customer_id}")
    
    # Fetch Google Ads data first (this is the critical path)
    spend_data = ads_manager.get_campaign_spend_data(customer_id, date_range)
    
    if spend_data is None:
        flash('Failed to fetch data. Please check your customer ID and API credentials.', 'error')
        return redirect(url_for('dashboard'))
    
    # Calculate totals
    total_spend = sum(item['cost'] for item in spend_data)
    total_clicks = sum(item['clicks'] for item in spend_data)
    total_impressions = sum(item['impressions'] for item in spend_data)
    
    print(f"📊 Data fetched successfully: {len(spend_data)} campaigns, ${total_spend:.2f} total spend")
    
    # Initialize AI insights as None
    ai_insights = None
    
    # Start AI analysis asynchronously if we have data and Replicate is available
    if replicate_analyst and len(spend_data) > 0:
        print("🤖 Starting AI analysis...")
        
        # Generate a unique key for this analysis
        analysis_key = f"{customer_id}_{int(time.time())}"
        
        def store_ai_result(result):
            ai_results_store[analysis_key] = result
            print(f"✅ AI analysis completed for key: {analysis_key}")
        
        # Start async analysis
        ai_insights = replicate_analyst.get_quick_insights_async(
            spend_data, total_spend, total_clicks, total_impressions, 
            callback=store_ai_result
        )
        ai_insights['analysis_key'] = analysis_key
    
    if len(spend_data) == 0:
        flash('No campaigns found for the specified date range.', 'info')
    else:
        flash(f'Successfully fetched data for {len(spend_data)} campaigns.', 'success')
    
    return render_template('results.html', 
                         spend_data=spend_data,
                         total_spend=total_spend,
                         total_clicks=total_clicks,
                         total_impressions=total_impressions,
                         customer_id=customer_id,
                         date_range=date_range,
                         ai_insights=ai_insights)

@app.route('/get_ai_insights/<analysis_key>')
def get_ai_insights(analysis_key):
    """Endpoint to poll for AI insights completion"""
    if analysis_key in ai_results_store:
        result = ai_results_store.pop(analysis_key)  # Remove after retrieval
        return jsonify(result)
    else:
        return jsonify({
            'success': False,
            'status': 'processing',
            'message': 'Analysis still in progress...'
        })

@app.route('/health')
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'ads_configured': session.get('ads_configured', False),
        'replicate_available': replicate_analyst is not None
    })