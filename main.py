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
    'https://www.googleapis.com/auth/spreadsheets', # Added for potential future use if integrating with Sheets
    'https://www.googleapis.com/auth/drive.metadata', # Added for potential future use if integrating with Drive
    'https://www.googleapis.com/auth/drive.file', # Added for potential future use if integrating with Drive
]
REDIRECT_URI = os.getenv('REDIRECT_URI')

# --- GoogleAdsManager Class (moved directly into app.py for simplicity in this response) ---
# In a larger project, you would keep this in a separate file like google_ads_manager.py
class GoogleAdsManager:
    def __init__(self, developer_token, client_id, client_secret, refresh_token, manager_customer_id, access_token=None):
        self.developer_token = developer_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.manager_customer_id = manager_customer_id  # This is the MANAGER account ID
        self.client = None
        
    def initialize_client(self):
        """Initialize Google Ads client with credentials and manager_customer_id as login_customer_id"""
        try:
            # Credentials dictionary
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
            
            # Always set login_customer_id to the manager's ID when initializing the client
            # This is crucial for accessing client accounts under the manager.
            if self.manager_customer_id:
                credentials["login_customer_id"] = str(self.manager_customer_id)
            
            self.client = GoogleAdsClient.load_from_dict(credentials)
            return True
        except Exception as e:
            print(f"Error initializing client: {e}")
            return False
    
    def is_manager_account(self, customer_id_to_check=None):
        """
        Check if the provided customer ID (or the manager's ID) is a manager account.
        Returns (True/False, error_message_str or None)
        """
        if not self.client:
            return False, "Client not initialized."
            
        target_customer_id = customer_id_to_check if customer_id_to_check else self.manager_customer_id

        try:
            ga_service = self.client.get_service("GoogleAdsService")
            query = f"""
                SELECT
                    customer.manager
                FROM customer
                WHERE customer.id = {target_customer_id}
            """
            
            response = ga_service.search(
                customer_id=str(target_customer_id),  
                query=query
            )
            for row in response:
                return row.customer.manager, None
            return False, None # No customer row found, implying it's not a manager or doesn't exist
        except GoogleAdsException as ex:
            error_messages = self._extract_google_ads_error_messages(ex, target_customer_id)
            return False, error_messages
        except Exception as e:
            return False, f"An unexpected error occurred while checking manager status: {str(e)}"
            
    def get_client_accounts(self):
        """
        Get client accounts under a manager account.
        Returns a tuple: (list_of_clients, error_message_str or None)
        """
        if not self.client:
            return [], "Client not initialized."
            
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
            
            response = ga_service.search(customer_id=str(self.manager_customer_id), query=query)
            clients = []
            
            for row in response:
                if not row.customer_client.manager:  
                    clients.append({
                        'id': row.customer_client.client_customer,
                        'name': row.customer_client.descriptive_name,
                        'currency': row.customer_client.currency_code,
                        'timezone': row.customer_client.time_zone,
                        'status': row.customer_client.status.name
                    })
            
            # If total_results_count is 0, but no exception, it means valid manager with no direct clients
            if not clients and hasattr(response, 'total_results_count') and response.total_results_count == 0:
                 return [], None

            return clients, None # Success
        except GoogleAdsException as ex:
            error_messages = self._extract_google_ads_error_messages(ex, self.manager_customer_id)
            return [], error_messages
        except Exception as e:
            return [], f"An unexpected error occurred while fetching client accounts: {str(e)}"
    
    def get_campaigns(self, customer_id_to_query=None):
        """
        Retrieve all campaigns for the specified customer ID.
        Returns a tuple: (list_of_campaigns, error_message_str or None)
        """
        if not self.client:
            return [], "Client not initialized."
        
        target_customer_id = customer_id_to_query if customer_id_to_query else self.manager_customer_id
        
        try:
            ga_service = self.client.get_service("GoogleAdsService")
            # --- MODIFIED QUERY HERE ---
            query = f"""
                SELECT
                    campaign.id,
                    campaign.name,
                    campaign.status,
                    metrics.cost_micros,
                    metrics.impressions,
                    metrics.clicks
                FROM campaign
                WHERE segments.date DURING LAST_30_DAYS
                ORDER BY campaign.name
            """
            
            response = ga_service.search(
                customer_id=str(target_customer_id),
                query=query
            )
            
            campaigns = []
            
            for row in response:
                campaign = {
                    'id': row.campaign.id,
                    'name': row.campaign.name,
                    'status': row.campaign.status.name,
                    'customer_id': target_customer_id # Add customer_id for context
                }
                
                # Add metrics if available
                if hasattr(row, 'metrics'):
                    campaign.update({
                        'impressions': row.metrics.impressions,
                        'clicks': row.metrics.clicks,
                        'cost': row.metrics.cost_micros / 1000000 if row.metrics.cost_micros else 0, # Convert micros to actual currency
                        'ctr': round(row.metrics.ctr * 100, 2) if hasattr(row.metrics, 'ctr') and row.metrics.ctr else 0.00 # CTR might not be in query, handle gracefully
                    })
                else:
                    campaign.update({ # Ensure keys are always present even if N/A
                        'impressions': 'N/A',
                        'clicks': 'N/A',
                        'cost': 'N/A',
                        'ctr': 'N/A'
                    })
                
                campaigns.append(campaign)
            
            # If the response iterable is exhausted without any campaigns, but no exception was raised
            # it means the ID was valid, but no campaigns found for the criteria.
            if not campaigns and hasattr(response, 'total_results_count') and response.total_results_count == 0:
                return [], None # Valid ID, but truly no campaigns
            
            return campaigns, None # Success, no error message
            
        except GoogleAdsException as ex:
            error_messages = self._extract_google_ads_error_messages(ex, target_customer_id)
            return [], error_messages
        except Exception as e:
            return [], f"An unexpected error occurred: {str(e)}"
            
    def get_ad_groups(self, campaign_id, customer_id_to_query=None):
        """
        Get ad groups for a specific campaign and customer ID.
        Returns a tuple: (list_of_ad_groups, error_message_str or None)
        """
        if not self.client:
            return [], "Client not initialized."
            
        target_customer_id = customer_id_to_query if customer_id_to_query else self.manager_customer_id
        
        try:
            ga_service = self.client.get_service("GoogleAdsService")
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
            
            response = ga_service.search(
                customer_id=str(target_customer_id),
                query=query
            )
            
            ad_groups = []
            
            for row in response:
                ad_group = {
                    'id': row.ad_group.id,
                    'name': row.ad_group.name,
                    'status': row.ad_group.status.name,
                    'campaign_id': campaign_id # Add campaign_id for context
                }
                
                if hasattr(row, 'metrics'):
                    ad_group.update({
                        'impressions': row.metrics.impressions,
                        'clicks': row.metrics.clicks,
                        'cost': row.metrics.cost_micros / 1000000 if row.metrics.cost_micros else 0
                    })
                else:
                    ad_group.update({
                        'impressions': 'N/A',
                        'clicks': 'N/A',
                        'cost': 'N/A'
                    })
                ad_groups.append(ad_group)
            
            if not ad_groups and hasattr(response, 'total_results_count') and response.total_results_count == 0:
                return [], None # Valid ID, no ad groups
            
            return ad_groups, None # Success
        except GoogleAdsException as ex:
            error_messages = self._extract_google_ads_error_messages(ex, target_customer_id)
            return [], error_messages
        except Exception as e:
            return [], f"An unexpected error occurred while fetching ad groups: {str(e)}"

    def _extract_google_ads_error_messages(self, ex, customer_id):
        """Helper to extract and format GoogleAdsException error messages."""
        error_details = []
        for error in ex.error:
            if error.error_code.authentication_error:
                if error.error_code.authentication_error == self.client.get_type('AuthenticationErrorEnum').AuthenticationError.CUSTOMER_NOT_FOUND:
                    error_details.append(f"Customer ID '{customer_id}' not found or you do not have direct access to it.")
                else: # Other authentication errors
                    error_details.append(f"Authentication Error: {error.message} (Code: {error.error_code.authentication_error.name})")
            elif error.error_code.authorization_error:
                if error.error_code.authorization_error == self.client.get_type('AuthorizationErrorEnum').AuthorizationError.USER_PERMISSION_DENIED:
                    error_details.append(f"Permission denied for Customer ID '{customer_id}'. Ensure the authenticated user has access and 'login-customer-id' is correct.")
                else: # Other authorization errors
                    error_details.append(f"Authorization Error: {error.message} (Code: {error.error_code.authorization_error.name})")
            else: # Generic Google Ads API errors
                error_details.append(f"Google Ads API Error: {error.message} (Code: {error.error_code.error_code_name})")
        
        # If no specific errors extracted, fallback to generic exception message
        return "; ".join(error_details) if error_details else str(ex)

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        developer_token = os.getenv('GOOGLE_DEVELOPER_TOKEN')
        
        if not developer_token:
            flash('Developer token not found in environment variables. Please check your .env file for GOOGLE_DEVELOPER_TOKEN.', 'error')
            return render_template('setup.html')
            
        session['developer_token'] = developer_token
        session['client_id'] = request.form['client_id']
        session['client_secret'] = request.form['client_secret']
        session['customer_id'] = request.form['customer_id'].replace('-', '') # Store manager ID without hyphens
        
        print(f"Session data stored:")
        print(f"Developer token present: {'Yes' if session.get('developer_token') else 'No'}")
        print(f"Client ID: {session.get('client_id', 'Not set')}")
        print(f"Customer ID (Manager ID): {session.get('customer_id', 'Not set')}")
        
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
            prompt='consent' # Force consent screen to ensure refresh token
        )
        
        session['state'] = state
        return redirect(authorization_url)
        
    return render_template('setup.html')

@app.route('/callback')
def callback():
    try:
        print(f"Callback - Session data check:")
        print(f"Developer token present: {'Yes' if session.get('developer_token') else 'No'}")
        print(f"Client ID present: {'Yes' if session.get('client_id') else 'No'}")
        
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
        flow.redirect_uri = REDIRECT_URI # Corrected spelling
        
        flow.fetch_token(authorization_response=request.url)
        
        if flow.credentials.refresh_token:
            session['refresh_token'] = flow.credentials.refresh_token
            session['access_token'] = flow.credentials.token
            session['authenticated'] = True
            flash('Successfully authenticated with Google Ads!', 'success')
            return redirect(url_for('dashboard'))
        else:
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

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    print(f"Dashboard - Session data check:")
    for key in ['authenticated', 'developer_token', 'client_id', 'client_secret', 'customer_id']:
        print(f"{key}: {'Present' if session.get(key) else 'Missing'}")
        
    if not session.get('authenticated'):
        flash('Please authenticate first', 'error')
        return redirect(url_for('setup'))
        
    required_fields = ['developer_token', 'client_id', 'client_secret', 'customer_id']
    missing_fields = [field for field in required_fields if not session.get(field)]
    
    if missing_fields:
        flash(f'Missing required credentials: {", ".join(missing_fields)}. Please try the setup process again.', 'error')
        return redirect(url_for('setup'))
        
    if not session.get('refresh_token') and not session.get('access_token'):
        flash('No authentication tokens found. Please authenticate again.', 'error')
        return redirect(url_for('setup'))
        
    ads_manager = GoogleAdsManager(
        session['developer_token'],
        session['client_id'],
        session['client_secret'],
        session.get('refresh_token'),
        session['customer_id'], # This is your MANAGER_CUSTOMER_ID
        session.get('access_token')
    )
    
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client. Please check your credentials.', 'error')
        return redirect(url_for('setup'))
        
    campaigns = []
    selected_client_id = None
    flash_message = None 
    flash_category = 'info' 

    is_manager_account, manager_error = ads_manager.is_manager_account(session['customer_id'])
    if manager_error:
        flash(f"Error checking manager status: {manager_error}", 'error')
        is_manager_account = False # Assume not manager if error checking

    if request.method == 'POST':
        selected_client_id = request.form.get('client_id')
        if selected_client_id:
            campaigns, error_message = ads_manager.get_campaigns(customer_id_to_query=selected_client_id)
            if error_message:
                flash_message = f'Error fetching campaigns for client ID {selected_client_id}: {error_message}'
                flash_category = 'error'
            elif campaigns:
                flash_message = f'Found {len(campaigns)} campaigns for client ID: {selected_client_id}'
                flash_category = 'success'
            else: 
                flash_message = f'No campaigns found for client ID: {selected_client_id}. This ID is valid, but there are no campaigns matching the criteria (e.g., active in last 30 days).'
                flash_category = 'warning'
        else:
            flash_message = 'Please enter a valid client ID.'
            flash_category = 'error'
            
    elif not is_manager_account: # If it's a GET request and not a manager, query primary account campaigns
        campaigns, error_message = ads_manager.get_campaigns(customer_id_to_query=session['customer_id'])
        if error_message:
            flash_message = f'Error fetching campaigns for your primary account: {error_message}'
            flash_category = 'error'
        elif campaigns:
            flash_message = f'Found {len(campaigns)} campaigns for your primary account.'
            flash_category = 'success'
        else:
            flash_message = 'No campaigns found for your primary account. This ID is valid, but there are no campaigns matching the criteria (e.g., active in last 30 days).'
            flash_category = 'warning'
    
    if flash_message:
        flash(flash_message, flash_category)

    return render_template('dashboard.html', 
                            campaigns=campaigns, 
                            is_manager=is_manager_account,
                            selected_client_id=selected_client_id,
                            manager_account_id=session['customer_id'])

@app.route('/clients')
def list_clients():
    if not session.get('authenticated'):
        flash('Please authenticate first', 'error')
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
        flash('Failed to initialize Google Ads client to fetch client accounts', 'error')
        return redirect(url_for('dashboard'))
        
    client_accounts, error_message = ads_manager.get_client_accounts()
    if error_message:
        flash(f'Error fetching client accounts: {error_message}', 'error')
        return redirect(url_for('dashboard'))
    elif not client_accounts:
        flash('No client accounts found under your manager account.', 'info')

    return render_template('clients.html', client_accounts=client_accounts)

@app.route('/client/<client_id>/campaigns')
def client_campaigns(client_id):
    if not session.get('authenticated'):
        flash('Please authenticate first', 'error')
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
        flash('Failed to initialize Google Ads client for selected client account', 'error')
        return redirect(url_for('dashboard'))
        
    campaigns, error_message = ads_manager.get_campaigns(customer_id_to_query=client_id)
    if error_message:
        flash(f'Error fetching campaigns for client ID {client_id}: {error_message}', 'error')
    elif not campaigns:
        flash(f'No campaigns found for client ID: {client_id}. This ID is valid, but there are no campaigns matching the criteria (e.g., active in last 30 days).', 'warning')
    else:
        flash(f'Found {len(campaigns)} campaigns for client ID: {client_id}.', 'success')
        
    client_accounts, client_error_message = ads_manager.get_client_accounts() # Fetch clients to find client_info
    client_info = next((c for c in client_accounts if str(c['id']) == client_id), None)
    if client_error_message:
        flash(f"Could not retrieve client details: {client_error_message}", 'error')

    return render_template('client_campaigns.html', 
                            campaigns=campaigns, 
                            client_info=client_info,
                            client_id=client_id)

@app.route('/campaign/<int:campaign_id>')
def campaign_detail(campaign_id):
    if not session.get('authenticated'):
        flash('Please authenticate first', 'error')
        return redirect(url_for('setup'))
        
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
        flash('Failed to initialize Google Ads client for campaign detail', 'error')
        return redirect(url_for('dashboard'))
        
    target_id_for_ad_groups = client_customer_id if client_customer_id else session['customer_id']
    ad_groups, error_message = ads_manager.get_ad_groups(campaign_id, customer_id_to_query=target_id_for_ad_groups)
    
    if error_message:
        flash(f'Error fetching ad groups for campaign {campaign_id}: {error_message}', 'error')
    elif not ad_groups:
        flash(f'No ad groups found for campaign {campaign_id}. This campaign is valid, but has no ad groups matching the criteria (e.g., active in last 30 days).', 'warning')
    else:
        flash(f'Found {len(ad_groups)} ad groups for campaign {campaign_id}.', 'success')

    # You might want to fetch campaign details here if you need to display them
    # For now, client_id is passed for context in the template
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
        
    campaigns, error_message = ads_manager.get_campaigns(customer_id_to_query=session['customer_id'])
    if error_message:
        return jsonify({'error': error_message}), 500
    
    return jsonify(campaigns)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/debug/env')
def debug_env():
    return {
        'GOOGLE_DEVELOPER_TOKEN_SET': 'Yes' if os.getenv('GOOGLE_DEVELOPER_TOKEN') else 'No',
        'SECRET_KEY_SET': 'Yes' if os.getenv('SECRET_KEY') else 'No',
        'REDIRECT_URI_SET': 'Yes' if os.getenv('REDIRECT_URI') else 'No',
    }
