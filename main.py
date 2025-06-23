from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
from datetime import datetime, timedelta
import json
from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import google.auth.exceptions
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configuration
SCOPES = [
    'https://www.googleapis.com/auth/adwords',
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive.metadata',
    'https://www.googleapis.com/auth/drive.file',
]
REDIRECT_URI = os.getenv('REDIRECT_URI')

class GoogleAdsManager:
    def __init__(self, developer_token, client_id, client_secret, refresh_token, customer_id, access_token=None):
        self.developer_token = developer_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.customer_id = customer_id
        self.client = None
        
    def initialize_client(self):
        """Initialize Google Ads client with credentials"""
        try:
            # Fixed credentials dictionary with all required fields
            credentials = {
                "developer_token": self.developer_token,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
                "token_uri": "https://oauth2.googleapis.com/token",
                "use_proto_plus": True
            }
            
            # Add access token if available
            if self.access_token:
                credentials["token"] = self.access_token
                
            self.client = GoogleAdsClient.load_from_dict(credentials)
            return True
        except Exception as e:
            print(f"Error initializing client: {e}")
            return False
    
    def is_manager_account(self):
        """Check if the customer ID is a manager account"""
        if not self.client:
            return False
            
        try:
            ga_service = self.client.get_service("GoogleAdsService")
            query = """
                SELECT
                    customer.manager
                FROM customer
                WHERE customer.id = {}
            """.format(self.customer_id)
            
            response = ga_service.search(customer_id=self.customer_id, query=query)
            for row in response:
                return row.customer.manager
            return False
        except Exception as e:
            print(f"Error checking manager status: {e}")
            return False
    
    def get_client_accounts(self):
        """Get client accounts under a manager account"""
        if not self.client:
            return []
            
        try:
            ga_service = self.client.get_service("GoogleAdsService")
            query = """
                SELECT
                    customer_client.client_customer,
                    customer_client.level,
                    customer_client.manager,
                    customer_client.descriptive_name,
                    customer_client.currency_code,
                    customer_client.time_zone,
                    customer_client.status
                FROM customer_client
                WHERE customer_client.level <= 1
            """
            
            response = ga_service.search(customer_id=self.customer_id, query=query)
            clients = []
            
            for row in response:
                if not row.customer_client.manager:  # Only non-manager accounts
                    clients.append({
                        'id': row.customer_client.client_customer,
                        'name': row.customer_client.descriptive_name,
                        'currency': row.customer_client.currency_code,
                        'timezone': row.customer_client.time_zone,
                        'status': row.customer_client.status.name
                    })
            
            return clients
        except GoogleAdsException as ex:
            print(f"Request failed getting clients: {ex}")
            return []
    
    def get_campaigns(self, client_customer_id=None):
        """Retrieve all campaigns for the customer or specific client"""
        if not self.client:
            return []
        
        # Use the provided client customer ID or the main customer ID
        target_customer_id = client_customer_id or self.customer_id
        
        try:
            ga_service = self.client.get_service("GoogleAdsService")
            
            # Check if this is a manager account trying to get metrics
            if not client_customer_id and self.is_manager_account():
                # For manager accounts, get campaigns without metrics
                query = """
                    SELECT
                        campaign.id,
                        campaign.name,
                        campaign.status,
                        campaign.advertising_channel_type
                    FROM campaign
                """
            else:
                # For client accounts, get campaigns with metrics
                query = """
                    SELECT
                        campaign.id,
                        campaign.name,
                        campaign.status,
                        campaign.advertising_channel_type,
                        metrics.impressions,
                        metrics.clicks,
                        metrics.cost_micros,
                        metrics.ctr
                    FROM campaign
                    WHERE segments.date DURING LAST_30_DAYS
                """
            
            response = ga_service.search(customer_id=str(target_customer_id), query=query)
            campaigns = []
            
            for row in response:
                campaign = {
                    'id': row.campaign.id,
                    'name': row.campaign.name,
                    'status': row.campaign.status.name,
                    'type': row.campaign.advertising_channel_type.name,
                    'customer_id': target_customer_id
                }
                
                # Add metrics if available (not for manager accounts)
                if hasattr(row, 'metrics'):
                    campaign.update({
                        'impressions': row.metrics.impressions,
                        'clicks': row.metrics.clicks,
                        'cost': row.metrics.cost_micros / 1000000,
                        'ctr': round(row.metrics.ctr * 100, 2)
                    })
                else:
                    # Default values for manager accounts
                    campaign.update({
                        'impressions': 'N/A',
                        'clicks': 'N/A',
                        'cost': 'N/A',
                        'ctr': 'N/A'
                    })
                
                campaigns.append(campaign)
            
            return campaigns
        except GoogleAdsException as ex:
            print(f"Request failed: {ex}")
            return []
    
    def get_ad_groups(self, campaign_id, client_customer_id=None):
        """Get ad groups for a specific campaign"""
        if not self.client:
            return []
        
        # Use the provided client customer ID or the main customer ID
        target_customer_id = client_customer_id or self.customer_id
        
        try:
            ga_service = self.client.get_service("GoogleAdsService")
            
            # Check if this is a manager account
            if not client_customer_id and self.is_manager_account():
                query = f"""
                    SELECT
                        ad_group.id,
                        ad_group.name,
                        ad_group.status,
                        ad_group.campaign
                    FROM ad_group
                    WHERE campaign.id = {campaign_id}
                """
            else:
                query = f"""
                    SELECT
                        ad_group.id,
                        ad_group.name,
                        ad_group.status,
                        ad_group.campaign,
                        metrics.impressions,
                        metrics.clicks,
                        metrics.cost_micros
                    FROM ad_group
                    WHERE campaign.id = {campaign_id}
                    AND segments.date DURING LAST_30_DAYS
                """
            
            response = ga_service.search(customer_id=str(target_customer_id), query=query)
            ad_groups = []
            
            for row in response:
                ad_group = {
                    'id': row.ad_group.id,
                    'name': row.ad_group.name,
                    'status': row.ad_group.status.name,
                }
                
                # Add metrics if available
                if hasattr(row, 'metrics'):
                    ad_group.update({
                        'impressions': row.metrics.impressions,
                        'clicks': row.metrics.clicks,
                        'cost': row.metrics.cost_micros / 1000000
                    })
                else:
                    ad_group.update({
                        'impressions': 'N/A',
                        'clicks': 'N/A',
                        'cost': 'N/A'
                    })
                
                ad_groups.append(ad_group)
            
            return ad_groups
        except GoogleAdsException as ex:
            print(f"Request failed: {ex}")
            return []

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        # Get developer token from environment variable
        developer_token = os.getenv('GOOGLE_DEVELOPER_TOKEN')
        
        # Debug: Check if developer token is loaded
        if not developer_token:
            flash('Developer token not found in environment variables. Please check your .env file for GOOGLE_DEVELOPER_TOKEN.', 'error')
            return render_template('setup.html')
        
        # Store user credentials in session
        session['developer_token'] = developer_token
        session['client_id'] = request.form['client_id']
        session['client_secret'] = request.form['client_secret']
        session['customer_id'] = request.form['customer_id']
        
        # Debug: Print session data (remove in production)
        print(f"Session data stored:")
        print(f"Developer token present: {'Yes' if session.get('developer_token') else 'No'}")
        print(f"Client ID: {session.get('client_id', 'Not set')}")
        print(f"Customer ID: {session.get('customer_id', 'Not set')}")
        
        # Create OAuth flow
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": session['client_id'],
                    "client_secret": session['client_secret'],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [REDIRECT_URI]
                }
            },
            scopes=SCOPES
        )
        flow.redirect_uri = REDIRECT_URI
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'  # Force consent screen to ensure refresh token
        )
        
        session['state'] = state
        return redirect(authorization_url)
    
    return render_template('setup.html')

@app.route('/callback')
def callback():
    try:
        # Debug: Check session data before processing
        print(f"Callback - Session data check:")
        print(f"Developer token present: {'Yes' if session.get('developer_token') else 'No'}")
        print(f"Client ID present: {'Yes' if session.get('client_id') else 'No'}")
        
        # Create flow with stored credentials
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": session['client_id'],
                    "client_secret": session['client_secret'],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [REDIRECT_URI]
                }
            },
            scopes=SCOPES,
            state=session['state']
        )
        flow.redirect_uri = REDIRECT_URI
        
        # Exchange authorization code for tokens
        flow.fetch_token(authorization_response=request.url)
        
        # Store tokens - handle both access and refresh tokens
        if flow.credentials.refresh_token:
            session['refresh_token'] = flow.credentials.refresh_token
            session['access_token'] = flow.credentials.token
            session['authenticated'] = True
            flash('Successfully authenticated with Google Ads!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Try to use access token directly if no refresh token
            if flow.credentials.token:
                session['access_token'] = flow.credentials.token
                session['authenticated'] = True
                flash('Authenticated successfully, but no refresh token received. You may need to re-authenticate when the token expires.', 'warning')
                return redirect(url_for('dashboard'))
            else:
                flash('No tokens received. Please try again or revoke access and re-authorize.', 'error')
                return redirect(url_for('setup'))
        
    except Exception as e:
        print(f"Callback error: {e}")
        flash(f'Authentication failed: {str(e)}', 'error')
        return redirect(url_for('setup'))

@app.route('/dashboard')
def dashboard():
    # Debug: Check session data
    print(f"Dashboard - Session data check:")
    for key in ['authenticated', 'developer_token', 'client_id', 'client_secret', 'customer_id']:
        print(f"{key}: {'Present' if session.get(key) else 'Missing'}")
    
    if not session.get('authenticated'):
        flash('Please authenticate first', 'error')
        return redirect(url_for('setup'))
    
    # Check if we have all required session data
    required_fields = ['developer_token', 'client_id', 'client_secret', 'customer_id']
    missing_fields = [field for field in required_fields if not session.get(field)]
    
    if missing_fields:
        flash(f'Missing required credentials: {", ".join(missing_fields)}. Please try the setup process again.', 'error')
        return redirect(url_for('setup'))
    
    # Check for tokens
    if not session.get('refresh_token') and not session.get('access_token'):
        flash('No authentication tokens found. Please authenticate again.', 'error')
        return redirect(url_for('setup'))
    
    # Initialize Google Ads manager
    ads_manager = GoogleAdsManager(
        session['developer_token'],
        session['client_id'],
        session['client_secret'],
        session.get('refresh_token'),
        session['customer_id'],
        session.get('access_token')
    )
    
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client. Please check your credentials.', 'error')
        return redirect(url_for('setup'))
    
    # Check if this is a manager account
    is_manager = ads_manager.is_manager_account()
    campaigns = []
    client_accounts = []
    
    if is_manager:
        # Get client accounts under the manager
        client_accounts = ads_manager.get_client_accounts()
        flash('This is a manager account. Select a client account below to view campaigns with metrics.', 'info')
    else:
        # Get campaigns for regular account
        campaigns = ads_manager.get_campaigns()
    
    return render_template('dashboard.html', 
                         campaigns=campaigns, 
                         client_accounts=client_accounts,
                         is_manager=is_manager)

# New route for client account campaigns
@app.route('/client/<client_id>/campaigns')
def client_campaigns(client_id):
    if not session.get('authenticated'):
        return redirect(url_for('setup'))
    
    ads_manager = GoogleAdsManager(
        session['developer_token'],
        session['client_id'],
        session['client_secret'],
        session.get('refresh_token'),
        session['customer_id'],
        session.get('access_token')
    )
    
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client', 'error')
        return redirect(url_for('dashboard'))
    
    campaigns = ads_manager.get_campaigns(client_customer_id=client_id)
    
    # Get client info
    client_accounts = ads_manager.get_client_accounts()
    client_info = next((c for c in client_accounts if str(c['id']) == client_id), None)
    
    return render_template('client_campaigns.html', 
                         campaigns=campaigns, 
                         client_info=client_info,
                         client_id=client_id)

@app.route('/campaign/<int:campaign_id>')
def campaign_detail(campaign_id):
    if not session.get('authenticated'):
        return redirect(url_for('setup'))
    
    # Get client_id from query parameter if provided (for manager accounts)
    client_customer_id = request.args.get('client_id')
    
    ads_manager = GoogleAdsManager(
        session['developer_token'],
        session['client_id'],
        session['client_secret'],
        session.get('refresh_token'),
        session['customer_id'],
        session.get('access_token')
    )
    
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client', 'error')
        return redirect(url_for('dashboard'))
    
    ad_groups = ads_manager.get_ad_groups(campaign_id, client_customer_id)
    return render_template('campaign_detail.html', 
                         ad_groups=ad_groups, 
                         campaign_id=campaign_id,
                         client_id=client_customer_id)

@app.route('/api/campaigns')
def api_campaigns():
    if not session.get('authenticated'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    ads_manager = GoogleAdsManager(
        session['developer_token'],
        session['client_id'],
        session['client_secret'],
        session.get('refresh_token'),
        session['customer_id'],
        session.get('access_token')
    )
    
    if not ads_manager.initialize_client():
        return jsonify({'error': 'Failed to initialize client'}), 500
    
    campaigns = ads_manager.get_campaigns()
    return jsonify(campaigns)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

# Debug route to check environment variables (remove in production)
@app.route('/debug/env')
def debug_env():
    return {
        'GOOGLE_DEVELOPER_TOKEN_SET': 'Yes' if os.getenv('GOOGLE_DEVELOPER_TOKEN') else 'No',
        'SECRET_KEY_SET': 'Yes' if os.getenv('SECRET_KEY') else 'No',
        'REDIRECT_URI_SET': 'Yes' if os.getenv('REDIRECT_URI') else 'No',
    }
