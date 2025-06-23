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
        """Check if the provided customer ID (or the manager's ID) is a manager account"""
        if not self.client:
            return False
            
        target_customer_id = customer_id_to_check if customer_id_to_check else self.manager_customer_id

        try:
            ga_service = self.client.get_service("GoogleAdsService")
            query = f"""
                SELECT
                    customer.manager
                FROM customer
                WHERE customer.id = {target_customer_id}
            """
            
            # For checking manager status, query the specific customer ID
            # The login_customer_id is already set during client initialization to the manager's ID
            response = ga_service.search(
                customer_id=str(target_customer_id),  
                query=query
            )
            for row in response:
                return row.customer.manager
            return False
        except Exception as e:
            print(f"Error checking manager status for {target_customer_id}: {e}")
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
            
            # Query the manager account to get its clients.
            # The login_customer_id is already set to the manager's ID.
            response = ga_service.search(customer_id=str(self.manager_customer_id), query=query)
            clients = []
            
            for row in response:
                # Filter out manager accounts themselves, we want true client accounts
                if not row.customer_client.manager:  
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
    
    def get_campaigns(self, customer_id_to_query=None):
        """Retrieve all campaigns for the specified customer ID"""
        if not self.client:
            return []
        
        # Use the customer_id_to_query if provided, otherwise default to the manager's ID
        target_customer_id = customer_id_to_query if customer_id_to_query else self.manager_customer_id
        
        try:
            ga_service = self.client.get_service("GoogleAdsService")
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
            
            # Perform the search on the target_customer_id.
            # The login_customer_id (manager_customer_id) is already set in the client object.
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
                    'type': row.campaign.advertising_channel_type.name,
                    'customer_id': target_customer_id
                }
                
                # Add metrics if available
                if hasattr(row, 'metrics'):
                    campaign.update({
                        'impressions': row.metrics.impressions,
                        'clicks': row.metrics.clicks,
                        'cost': row.metrics.cost_micros / 1000000 if row.metrics.cost_micros else 0,
                        'ctr': round(row.metrics.ctr * 100, 2) if row.metrics.ctr else 0.00
                    })
                else:
                    campaign.update({
                        'impressions': 'N/A',
                        'clicks': 'N/A',
                        'cost': 'N/A',
                        'ctr': 'N/A'
                    })
                
                campaigns.append(campaign)
            
            return campaigns
        except GoogleAdsException as ex:
            print(f"Request failed getting campaigns for customer ID {target_customer_id}: {ex}")
            return []
            
    def get_ad_groups(self, campaign_id, customer_id_to_query=None):
        """Get ad groups for a specific campaign and customer ID"""
        if not self.client:
            return []
            
        # Use the customer_id_to_query if provided, otherwise default to the manager's ID
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
            
            # Perform the search on the target_customer_id.
            # The login_customer_id (manager_customer_id) is already set in the client object.
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
                }
                
                # Add metrics if available
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
            
            return ad_groups
        except GoogleAdsException as ex:
            print(f"Request failed getting ad groups for campaign {campaign_id} in customer ID {target_customer_id}: {ex}")
            return []

# Routes
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
        flow.redirect_uri = REDEDICT_URI
        
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
        
    # Initialize Google Ads manager with the manager_customer_id (from session)
    ads_manager = GoogleAdsManager(
        session['developer_token'],
        session['client_id'],
        session['client_secret'],
        session.get('refresh_token'),
        session['customer_id'], # This is your MANAGER_CUSTOMER_ID
        session.get('access_token')
    )
    
    # Initialize the client. The login_customer_id will be set internally to session['customer_id']
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client. Please check your credentials.', 'error')
        return redirect(url_for('setup'))
        
    campaigns = []
    selected_client_id = None
    
    # Check if the primary customer_id (from session) is a manager account
    is_manager_account = ads_manager.is_manager_account(session['customer_id'])

    # Handle POST request (form submission with client ID for manager accounts)
    if request.method == 'POST':
        selected_client_id = request.form.get('client_id')
        if selected_client_id:
            try:
                # For client accounts, simply call get_campaigns with the client ID.
                # The ads_manager object is already initialized with the manager_customer_id as login_customer_id.
                campaigns = ads_manager.get_campaigns(customer_id_to_query=selected_client_id)
                if campaigns:
                    flash(f'Found {len(campaigns)} campaigns for client ID: {selected_client_id}', 'success')
                else:
                    flash(f'No campaigns found for client ID: {selected_client_id}', 'warning')
            except Exception as e:
                flash(f'Error fetching campaigns for client ID {selected_client_id}: {str(e)}', 'error')
        else:
            flash('Please enter a valid client ID', 'error')
            
    # For GET request, or if no campaigns found from POST,
    # and if the current account is NOT a manager account, try to get its campaigns.
    elif not is_manager_account:
        try:
            # Query campaigns for the primary account (which is not a manager in this branch)
            campaigns = ads_manager.get_campaigns(customer_id_to_query=session['customer_id'])
            if campaigns:
                flash(f'Found {len(campaigns)} campaigns for your primary account.', 'success')
            else:
                flash('No campaigns found for your primary account.', 'warning')
        except Exception as e:
            flash(f'Error fetching campaigns for your primary account: {str(e)}', 'error')
            
    return render_template('dashboard.html', 
                            campaigns=campaigns, 
                            is_manager=is_manager_account,
                            selected_client_id=selected_client_id,
                            manager_account_id=session['customer_id'])

# Route to list client accounts under manager account
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
        session['customer_id'], # This is your MANAGER_CUSTOMER_ID
        session.get('access_token')
    )
    
    # Initialize the client. The login_customer_id will be set internally to session['customer_id']
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client to fetch client accounts', 'error')
        return redirect(url_for('dashboard'))
        
    try:
        client_accounts = ads_manager.get_client_accounts()
        return render_template('clients.html', client_accounts=client_accounts)
    except Exception as e:
        flash(f'Error fetching client accounts: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

# New route for client account campaigns
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
        session['customer_id'], # This is your MANAGER_CUSTOMER_ID
        session.get('access_token')
    )
    
    # Initialize the client. The login_customer_id will be set internally to session['customer_id']
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client for selected client account', 'error')
        return redirect(url_for('dashboard'))
        
    campaigns = ads_manager.get_campaigns(customer_id_to_query=client_id)
    
    # Get client info (you might need to fetch this separately or pass it from the clients list)
    # For simplicity, we'll try to fetch it again, but in a real app you might pass it from /clients
    # NOTE: Calling get_client_accounts here means another API call, consider caching or passing data.
    client_accounts = ads_manager.get_client_accounts() # Fetch clients from the manager context
    client_info = next((c for c in client_accounts if str(c['id']) == client_id), None)
    
    return render_template('client_campaigns.html', 
                            campaigns=campaigns, 
                            client_info=client_info,
                            client_id=client_id)

@app.route('/campaign/<int:campaign_id>')
def campaign_detail(campaign_id):
    if not session.get('authenticated'):
        flash('Please authenticate first', 'error')
        return redirect(url_for('setup'))
        
    client_customer_id = request.args.get('client_id') # Get client_id from query parameter if provided
    
    ads_manager = GoogleAdsManager(
        session['developer_token'],
        session['client_id'],
        session['client_secret'],
        session.get('refresh_token'),
        session['customer_id'], # This is your MANAGER_CUSTOMER_ID
        session.get('access_token')
    )
    
    # Initialize the client. The login_customer_id will be set internally to session['customer_id']
    if not ads_manager.initialize_client():
        flash('Failed to initialize Google Ads client for campaign detail', 'error')
        return redirect(url_for('dashboard'))
        
    # Get ad groups for the specified campaign and target customer_id
    # If client_customer_id is provided, it means we are looking at a client's campaign
    target_id_for_ad_groups = client_customer_id if client_customer_id else session['customer_id']
    ad_groups = ads_manager.get_ad_groups(campaign_id, customer_id_to_query=target_id_for_ad_groups)
    
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
        
    # This endpoint currently fetches campaigns for the main customer_id (manager or single account)
    campaigns = ads_manager.get_campaigns(customer_id_to_query=session['customer_id'])
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
