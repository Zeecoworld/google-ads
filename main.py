from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import os
from urllib.parse import urlencode
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv() 

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-here')

# Only YOUR Developer Token needs to be in env (this is your app's token)
GOOGLE_DEVELOPER_TOKEN = os.environ.get('GOOGLE_DEVELOPER_TOKEN')

# Google OAuth2 endpoints
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_ADS_API_BASE = 'https://googleads.googleapis.com'

# Scopes required for Google Ads API
SCOPES = [
    'https://www.googleapis.com/auth/adwords',
    'openid',
    'email',
    'profile'
]

# In-memory storage for user sessions and tokens
user_sessions = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Allow user to enter their Google OAuth credentials"""
    if request.method == 'POST':
        # Store user's credentials in session
        session['google_client_id'] = request.form.get('client_id')
        session['google_client_secret'] = request.form.get('client_secret')
        session['redirect_uri'] = request.form.get('redirect_uri') or 'http://localhost:5000/callback'
        session['customer_id'] = request.form.get('customer_id')  # Their Ads Manager ID
        
        # Validate required fields
        if not all([session.get('google_client_id'), session.get('google_client_secret')]):
            return render_template('setup.html', error="Client ID and Client Secret are required")
        
        return redirect(url_for('initiate_auth'))
    
    return render_template('setup.html')

@app.route('/initiate_auth')
def initiate_auth():
    """Start OAuth2 flow with user's credentials"""
    client_id = session.get('google_client_id')
    redirect_uri = session.get('redirect_uri')
    
    if not client_id:
        return redirect(url_for('setup'))
    
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': ' '.join(SCOPES),
        'response_type': 'code',
        'access_type': 'offline',  # Important: to get refresh token
        'prompt': 'consent'  # Force consent screen to ensure refresh token
    }
    
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Handle OAuth2 callback and exchange code for tokens"""
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return render_template('error.html', error=f"Authorization failed: {error}")
    
    if not code:
        return render_template('error.html', error="No authorization code received")
    
    # Get user's credentials from session
    client_id = session.get('google_client_id')
    client_secret = session.get('google_client_secret')
    redirect_uri = session.get('redirect_uri')
    
    if not all([client_id, client_secret]):
        return redirect(url_for('setup'))
    
    # Exchange authorization code for access token and refresh token
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri
    }
    
    try:
        response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        response.raise_for_status()
        tokens = response.json()
        
        # Get user info
        user_info = get_user_info(tokens['access_token'])
        
        # Create unique session ID
        session_id = f"{user_info['id']}_{datetime.now().timestamp()}"
        
        # Store tokens and user credentials
        user_sessions[session_id] = {
            'access_token': tokens['access_token'],
            'refresh_token': tokens.get('refresh_token'),
            'expires_at': datetime.now() + timedelta(seconds=tokens.get('expires_in', 3600)),
            'user_info': user_info,
            'client_id': client_id,
            'client_secret': client_secret,
            'customer_id': session.get('customer_id')
        }
        
        # Store session ID
        session['session_id'] = session_id
        
        return redirect(url_for('dashboard'))
        
    except requests.RequestException as e:
        return render_template('error.html', error=f"Token exchange failed: {str(e)}")

@app.route('/dashboard')
def dashboard():
    """Dashboard showing user info and available actions"""
    session_id = session.get('session_id')
    if not session_id or session_id not in user_sessions:
        return redirect(url_for('setup'))
    
    user_data = user_sessions[session_id]
    return render_template('dashboard.html', 
                         user_info=user_data['user_info'],
                         customer_id=user_data.get('customer_id'))

@app.route('/accounts')
def get_accounts():
    """Fetch Google Ads accounts accessible by the user"""
    session_id = session.get('session_id')
    if not session_id or session_id not in user_sessions:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        access_token = get_valid_access_token(session_id)
        accounts = fetch_google_ads_accounts(access_token)
        return jsonify(accounts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/campaigns')
def get_campaigns():
    """Fetch campaigns for the user's specified customer ID"""
    session_id = session.get('session_id')
    if not session_id or session_id not in user_sessions:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_data = user_sessions[session_id]
    customer_id = request.args.get('customer_id') or user_data.get('customer_id')
    
    if not customer_id:
        return jsonify({'error': 'Customer ID required'}), 400
    
    try:
        access_token = get_valid_access_token(session_id)
        campaigns = fetch_campaigns(access_token, customer_id)
        return jsonify(campaigns)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/campaign-performance')
def get_campaign_performance():
    """Fetch campaign performance data"""
    session_id = session.get('session_id')
    if not session_id or session_id not in user_sessions:
        return jsonify({'error': 'Not authenticated'}), 401
    
    customer_id = request.args.get('customer_id')
    campaign_id = request.args.get('campaign_id')
    
    if not all([customer_id, campaign_id]):
        return jsonify({'error': 'Customer ID and Campaign ID required'}), 400
    
    try:
        access_token = get_valid_access_token(session_id)
        performance = fetch_campaign_performance(access_token, customer_id, campaign_id)
        return jsonify(performance)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    session_id = session.get('session_id')
    if session_id and session_id in user_sessions:
        del user_sessions[session_id]
    session.clear()
    return redirect(url_for('index'))

def get_user_info(access_token):
    """Get user information from Google"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers)
    response.raise_for_status()
    return response.json()

def get_valid_access_token(session_id):
    """Get a valid access token, refreshing if necessary"""
    user_data = user_sessions[session_id]
    
    # Check if token is expired
    if datetime.now() >= user_data['expires_at']:
        if user_data['refresh_token']:
            # Refresh the token using user's credentials
            refresh_data = {
                'client_id': user_data['client_id'],
                'client_secret': user_data['client_secret'],
                'refresh_token': user_data['refresh_token'],
                'grant_type': 'refresh_token'
            }
            
            response = requests.post(GOOGLE_TOKEN_URL, data=refresh_data)
            response.raise_for_status()
            tokens = response.json()
            
            # Update stored tokens
            user_data['access_token'] = tokens['access_token']
            user_data['expires_at'] = datetime.now() + timedelta(seconds=tokens.get('expires_in', 3600))
            
            return tokens['access_token']
        else:
            raise Exception("No refresh token available, user needs to re-authenticate")
    
    return user_data['access_token']

def fetch_google_ads_accounts(access_token):
    """Fetch Google Ads accounts using the Google Ads API"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'developer-token': GOOGLE_DEVELOPER_TOKEN,
        'Content-Type': 'application/json'
    }
    
    # First, get the list of accessible customers
    url = f"{GOOGLE_ADS_API_BASE}/v16/customers:listAccessibleCustomers"
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return {'error': f'API request failed: {response.status_code}', 'details': response.text}
    except Exception as e:
        return {'error': str(e)}

def fetch_campaigns(access_token, customer_id):
    """Fetch campaigns for a specific customer"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'developer-token': GOOGLE_DEVELOPER_TOKEN,
        'Content-Type': 'application/json'
    }
    
    query = """
        SELECT 
            campaign.id, 
            campaign.name, 
            campaign.status, 
            campaign.advertising_channel_type,
            campaign.start_date,
            campaign.end_date
        FROM campaign
        ORDER BY campaign.name
    """
    
    url = f"{GOOGLE_ADS_API_BASE}/v16/customers/{customer_id}/googleAds:searchStream"
    data = {'query': query}
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'API request failed: {response.status_code}', 'details': response.text}
    except Exception as e:
        return {'error': str(e)}

def fetch_campaign_performance(access_token, customer_id, campaign_id):
    """Fetch campaign performance metrics"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'developer-token': GOOGLE_DEVELOPER_TOKEN,
        'Content-Type': 'application/json'
    }
    
    query = f"""
        SELECT 
            campaign.id,
            campaign.name,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.ctr,
            metrics.average_cpc,
            segments.date
        FROM campaign
        WHERE campaign.id = {campaign_id}
        AND segments.date DURING LAST_30_DAYS
        ORDER BY segments.date DESC
    """
    
    url = f"{GOOGLE_ADS_API_BASE}/v16/customers/{customer_id}/googleAds:searchStream"
    data = {'query': query}
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'API request failed: {response.status_code}', 'details': response.text}
    except Exception as e:
        return {'error': str(e)}