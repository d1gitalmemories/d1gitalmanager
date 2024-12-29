from flask import Flask, Response, redirect, request, session, render_template
from waitress import serve
import random
import threading
import datetime
import string
import json
import discord
from discord.ext import commands
import requests
import sys
import os
import sqlite3
import platform
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import asyncio
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app)

######################### SECURITY HEADERS/CONFIGS --- IGNORE ####################
@app.before_request
def redirect_to_https():
    is_https = (
        request.headers.get("X-Forwarded-Proto", "http") == "https"
        or request.headers.get("CF-Visitor", "").startswith('{"scheme":"https"}')
    )
    if not is_https and not app.debug:
        app.logger.info(f"Redirecting {request.url} to HTTPS.")
        return redirect(request.url.replace("http://", "https://"), code=301)

@app.after_request
def apply_security_headers(response: Response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), autoplay=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    )
    return response

def load_config(file_path):
    try:
        with open(file_path, 'r') as config_file:
            config = json.load(config_file)
        return config
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading the configuration file: {e}")
        return None
    
config_path = "config.json"
config = load_config(config_path)

token = config.get("token")
clientID = config.get("clientID")
secret = config.get("secret")
redirecturl = config.get("redirecturl")
memberID = config.get("memberRoleID")
clientRoleID = config.get("clientRoleID")
flaskkey = config.get("flask-key")
guildID = config.get("guildID")
guild = discord.Object(id=guildID)
app.secret_key = flaskkey

intents = discord.Intents.all()
bot = commands.Bot(command_prefix='s!', intents=intents)

@bot.command(name="sync")
async def sync(ctx):
    try:
        await ctx.message.delete()
        synced = await bot.tree.sync(guild=guild)
        msg = await ctx.send(f'Synced {len(synced)} commands.')
        await asyncio.sleep(3)
    except Exception as e:
        print(f'Failed to sync commands: {e}')
@bot.event
async def on_ready():
    os.system("clear")
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.listening, name="d1gitalworlds"))
    system_info = {
        "Bot Name": bot.user.name,
        "Bot ID": bot.user.id,
        "Discord.py Version": discord.__version__,
        "Operating System": f"{platform.system()} {platform.release()} ({platform.architecture()[0]})",
        "Network Name": platform.node(),
        "OS Version": platform.version(),
        "Python Version": sys.version,
    }
    
    print("\n" + "="*40)
    print(" Bot Information ".center(40, "="))
    print("="*40)
    
    for key, value in system_info.items():
        print(f"{key:20}: {value}")
    
    print("="*40 + "\n")

######################### SECURITY HEADERS/CONFIGS --- IGNORE ####################

def delete_verified_user(discord_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Delete the user's record if they are verified
    cursor.execute("DELETE FROM members WHERE discord_id = ?", (discord_id,))
    conn.commit()
    conn.close()
    print(f"Record for Discord ID {discord_id} deleted from database.")
    
@bot.event
async def on_member_remove(member):
    discord_id = str(member.id)
    
    # Check if the user is verified (exists in the database)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM members WHERE discord_id = ?", (discord_id,))
    result = cursor.fetchone()
    conn.close()
    
    # If the user is verified, delete their record from the database
    if result:
        delete_verified_user(discord_id)
        print(f"User {discord_id} was verified and has been removed from the database.")

def is_vpn(ip_address):
    API_key = "d97f9a3357c3472e8481eaec3ea186dd"  # API key (you can change it with yours )
    response = requests.get(f"https://vpnapi.io/api/{ip_address}?key={API_key}")
    data = json.loads(response.text)
    return data["security"]["vpn"]

# Function to generate random strings for state and nonce
def generate_token(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@bot.tree.command(name="verify", guild=guild)
async def verify(interaction: discord.Interaction):
    # Get the user who invoked the command (the one who called /verify)
    member = interaction.user

    # Check if the user is already verified
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT roblox_id FROM members WHERE discord_id = ?", (str(member.id),))
    result = cursor.fetchone()
    conn.close()

    # If the user is already verified, inform them
    if result:
        await interaction.response.send_message(f"{member.display_name} is already verified!", ephemeral=True)
        return

    # Check if the user has an existing session token in the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT session_token FROM session_tokens WHERE discord_id = ?", (str(member.id),))
    result = cursor.fetchone()
    conn.close()

    # If no session token exists or the token has expired, create a new one
    if not result:
        session_token = generate_token()  # Generate new session token

        # Save the session token in the database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO session_tokens (discord_id, session_token) VALUES (?, ?)", (str(member.id), session_token))
        conn.commit()
        conn.close()

        # Send the new verification link to the user
        auth_url = f"https://auth.d1gitalmemories.fun/login/{member.id}?token={session_token}"
        await member.send(f"> <@{member.id}>, use this link to verify here: {auth_url}.")
        await interaction.response.send_message(f"A new verification link has been sent to {member.display_name}.", ephemeral=True)

    else:
        await interaction.response.send_message(f"A session already exists for {member.display_name}, but the token may have expired. A new link has been sent.", ephemeral=True)
        
        # Generate and store a new session token
        session_token = generate_token()
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE session_tokens SET session_token = ? WHERE discord_id = ?", (session_token, str(member.id)))
        conn.commit()
        conn.close()

        # Send the new verification link
        auth_url = f"https://auth.d1gitalmemories.fun/login/{member.id}?token={session_token}"
        await member.send(f"> <@{member.id}>, use this link to verify here: {auth_url}.")


@bot.event
async def on_member_join(member):
    user_id = member.id
    session_token = generate_token()  # Generate session token
    
    # Save the session token in the database or session
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO session_tokens (discord_id, session_token) VALUES (?, ?)", (user_id, session_token))
    conn.commit()
    conn.close()
    
    auth_url = f"https://auth.d1gitalmemories.fun/login/{user_id}?token={session_token}"
    await member.send(f"> <@{user_id}>, use this link to verify here: {auth_url}.")

# Helper function to check verification status
def is_already_verified(discord_id):
    conn = sqlite3.connect('database.db')  # Replace with your SQLite database
    cursor = conn.cursor()
    cursor.execute("SELECT roblox_id FROM members WHERE discord_id = ?", (discord_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

# Helper function to check if a Roblox account is already linked
def is_roblox_account_linked(roblox_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT discord_id FROM members WHERE roblox_id = ?", (roblox_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

@bot.tree.command(name="exile", guild=guild)
async def exile(interaction: discord.Interaction, member: discord.Member):
    # Ensure the user has the proper permissions to exile someone
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("You do not have permission to exile members.", ephemeral=True)
        return

    try:
        # Remove all roles except the @everyone role
        await member.edit(roles=[interaction.guild.default_role])
        print(f"Removed all roles from {member.display_name}.")
    except discord.Forbidden:
        await interaction.response.send_message("I don't have permission to remove roles from this user.", ephemeral=True)
        return
    
    try:
        await member.edit(nick=None)
        print(f"Reset {member.display_name}'s nickname.")
    except discord.Forbidden:
        await interaction.response.send_message("I don't have permission to reset the user's nickname.", ephemeral=True)
        return

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM members WHERE discord_id = ?", (str(member.id),))
        cursor.execute("DELETE FROM session_tokens WHERE discord_id = ?", (str(member.id),))
        conn.commit()
        conn.close()
        print(f"Removed {member.display_name} from the database.")
    except sqlite3.Error as e:
        await interaction.response.send_message(f"An error occurred while removing the user from the database: {e}", ephemeral=True)
        return

    # Notify the user that the exile was successful
    await interaction.response.send_message(f"{member.display_name} has been exiled and removed from the database.", ephemeral=True)

@app.route('/terms-of-service', methods=['GET'])
def tos():
    return render_template('terms.html')

@app.route('/privacy-policy', methods=['GET'])
def privacy():
    return render_template('privacy.html')

@app.route('/', methods=['GET'])
def home():
    return redirect('https://d1gitalmemories.fun/')

@app.route('/login/<discord_id>', methods=['GET'])
@limiter.limit("10 per minute") 
def login(discord_id):
    user_token = request.args.get('token')
    
    if is_already_verified(discord_id):
        return render_template("status.html", message="Authentication failed!", custom_message="You are already verified.", success=False)
    
    ip_address = request.remote_addr
    vpn_status = is_vpn(ip_address)
    if vpn_status:
        return render_template("status.html", message="Authentication failed!", custom_message="VPN/Proxies are not allowed.", success=False)

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT session_token FROM session_tokens WHERE discord_id = ?", (discord_id,))
    result = cursor.fetchone()
    conn.close()

    if result is None or result[0] != user_token:
        return render_template("status.html", message="Invalid or expired verification link. Please try again.")
    state = generate_token(16)
    nonce = generate_token(16)
    expiration_time = datetime.now(timezone.utc) + timedelta(minutes=5)

    session['state'] = state
    session['nonce'] = nonce
    session['discord_id'] = discord_id
    session['expiration_time'] = expiration_time

    # Construct the Roblox authorization URL
    authorize_url = f"https://apis.roblox.com/oauth/v1/authorize?" \
                    f"response_type=code&client_id={clientID}&" \
                    f"redirect_uri={redirecturl}&scope=openid+profile&" \
                    f"state={state}&nonce={nonce}&step=accountConfirm"

    print(f"Redirecting to Roblox: {authorize_url}")  # Debugging output

    return redirect(authorize_url)

@app.route('/oauth/callback', methods=['GET'])
@limiter.limit("5 per minute")
def callback():
    ip_address = request.remote_addr
    vpn_status = is_vpn(ip_address)
    if vpn_status:
        return render_template("status.html", message="VPN/Proxies are not allowed.")
    code = request.args.get('code')
    state = request.args.get('state')
    expiration_time = session.get('expiration_time')
    discord_id = session.get('discord_id')

    if state != session.get('state'):
        return render_template("status.html", message="Authentication failed!", custom_message="Invalid request. Please restart the verification process.", success=False)
    
    if expiration_time and datetime.now(timezone.utc) > expiration_time:
        return render_template("status.html", message="Authentication failed!", custom_message="Authorization link has expired. Please restart the process.", success=False)

    # Now exchange the authorization code for an access token
    token_url = 'https://apis.roblox.com/oauth/v1/token'
    redirect_uri = redirecturl

    data = {
        'code': code,
        'client_id': clientID,
        'client_secret': secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }

    response = requests.post(token_url, data=data)

    if response.status_code == 200:
        # Successfully obtained the token, store it in the session
        token_data = response.json()
        session['access_token'] = token_data['access_token']
        session['refresh_token'] = token_data.get('refresh_token')

        # Optionally, get user info with the access token
        user_info_url = 'https://apis.roblox.com/oauth/v1/userinfo'
        user_info_response = requests.get(user_info_url, headers={
            'Authorization': f"Bearer {session['access_token']}"
        })

        if user_info_response.status_code == 200:
            user_info = user_info_response.json()

            # Convert created_at timestamp to a human-readable format
            created_at_timestamp = user_info.get('created_at')
            if created_at_timestamp:
                created_at = datetime.fromtimestamp(created_at_timestamp, timezone.utc)
                created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S')
            else:
                created_at_str = 'Unknown'

            created_at_lol = datetime.strptime(created_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            current_date = datetime.now(timezone.utc)
            account_age_days = (current_date - created_at_lol).days
            if account_age_days < 30:
                return render_template("status.html", message="Authentication failed!", custom_message="Account not old enough. Must be at least 30 days old.", success=False)

            roblox_username = user_info.get('preferred_username')
            roblox_id = user_info.get('sub')
            discord_id = session.get('discord_id')

            if is_roblox_account_linked(roblox_id):
                return render_template("status.html", message="Authentication failed!", custom_message="This Roblox account is already linked to another Discord account.", success=False)
            
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO members (discord_id, roblox_id, roblox_username) VALUES (?, ?, ?)",
                   (discord_id, roblox_id, roblox_username))
            conn.commit()
            conn.close()

            async def ping_discord_user():
               guild = bot.get_guild(guildID)
               memberIDObject = discord.utils.get(guild.roles, id=int(memberID))
               member = await guild.fetch_member(discord_id) 
               await member.add_roles(memberIDObject)
               user = await bot.fetch_user(discord_id)
               await member.edit(nick=roblox_username)
               await user.send(f"> <@{discord_id}>, you now have successfully verified as **{roblox_username}**. Welcome to d1gitalworlds and I hope you enjoy your stay here.")
                    
            bot.loop.create_task(ping_discord_user())
            return render_template("status.html", message="Authentication successful!", custom_message="Authorization is successful! You can now close this page.", success=True)
        
        return "User info could not be fetched.", 400
    else:
        return f"Error exchanging code for token: {response.text}", 400

    
def run_flask():
    serve(app, host='0.0.0.0', port=21392)

if __name__ == "__main__":
    threading.Thread(target=run_flask).start()
    bot.run(token)