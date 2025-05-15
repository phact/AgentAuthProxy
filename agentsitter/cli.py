import os
import sys
import json
import time

import dotenv
import requests
import click
import asyncio
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from agentsitter.cancel_wait_redirect import CancelWaitRedirectAddon

dotenv.load_dotenv()

# Configuration
CONFIG_DIR = os.path.expanduser("~/.agentsitter")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
#NOTIFY_URL = os.getenv("AGENTSITTER_NOTIFY_URL", "https://agentsitter.ai")
NOTIFY_URL = os.getenv("AGENTSITTER_NOTIFY_URL", "http://localhost:5001")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")

# Utility functions
def save_config(data):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(data, f)


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)


def get_token():
    config = load_config()
    token = config.get('token')
    if not token:
        github_device_flow()
        return get_token()
    return token

# OAuth Device Flow
def github_device_flow():
    if not GITHUB_CLIENT_ID:
        click.echo("Error: GITHUB_CLIENT_ID environment variable not set.")
        sys.exit(1)

    # request device code
    resp = requests.post(
        "https://github.com/login/device/code",
        data={"client_id": GITHUB_CLIENT_ID, "scope": "read:user"},
        headers={"Accept": "application/json"}
    )
    resp.raise_for_status()
    data = resp.json()
    device_code = data['device_code']
    user_code = data['user_code']
    verification_uri = data['verification_uri']
    interval = data.get('interval', 5)

    click.echo(f"Open {verification_uri} and enter code: {user_code}")

    # poll for token
    token = None
    while True:
        time.sleep(interval)
        token_resp = requests.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
            },
            headers={"Accept": "application/json"}
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        if token_data.get('error'):
            if token_data['error'] == 'authorization_pending':
                continue
            else:
                click.echo(f"Error during OAuth: {token_data.get('error_description', token_data['error'])}")
                sys.exit(1)
        token = token_data['access_token']
        break

    # Save token
    save_config({'token': token})
    click.echo("Login successful!")

# CLI Commands
@click.group()
def cli():
    """agentsitter.ai CLI: intercept AI agent HTTP traffic with human approval"""
    pass

@cli.command()
def login():
    """Login via GitHub OAuth Device Flow"""
    github_device_flow()

@cli.command()
def run():
    """Start the agentsitter.ai CLI (runs mitmproxy and listens for approvals)"""
    token = get_token()

    # Create an event loop explicitly
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Start mitmproxy with the explicit loop
    opts = Options(listen_host='127.0.0.1', listen_port=8080, ssl_insecure=True)
    m = DumpMaster(opts, loop)

    m.addons.add(CancelWaitRedirectAddon(NOTIFY_URL, token))

    try:
        loop.run_until_complete(m.run())
    except KeyboardInterrupt:
        loop.run_until_complete(m.shutdown())
    finally:
        loop.close()

if __name__ == '__main__':
    cli()
