# notion.py

import json
import secrets
import base64
import os
import urllib.parse
import asyncio
import httpx
import requests

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse

from dotenv import load_dotenv
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

load_dotenv()

# --- Config ---
CLIENT_ID = os.getenv('NOTION_CLIENT_ID')
CLIENT_SECRET = os.getenv('NOTION_CLIENT_SECRET')
REDIRECT_URI = "http://localhost:8000/integrations/notion/oauth2callback"

encoded_client_id_secret = base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
).decode()


# --- Step 1: Authorization ---
async def authorize_notion(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }
    state_json = json.dumps(state_data)

    # Save state in Redis
    await add_key_value_redis(f"notion_state:{org_id}:{user_id}", state_json, expire=600)

    # Encode state + redirect_uri
    encoded_state = urllib.parse.quote(state_json, safe="")
    encoded_redirect_uri = urllib.parse.quote(REDIRECT_URI, safe="")

    # Build the correct Notion OAuth URL
    final_url = (
        f"https://www.notion.com/oauth2/v2.0/authorize"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&owner=user"
        f"&redirect_uri={encoded_redirect_uri}"
        f"&state={encoded_state}"
    )

    print("DEBUG Notion Auth URL:", final_url)
    return final_url


# --- Step 2: OAuth Callback ---
async def oauth2callback_notion(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error"))

    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")

    try:
        state_data = json.loads(urllib.parse.unquote(encoded_state))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state format")

    original_state = state_data.get("state")
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")

    saved_state = await get_value_redis(f"notion_state:{org_id}:{user_id}")

    if not saved_state or original_state != json.loads(saved_state).get("state"):
        raise HTTPException(status_code=400, detail="State does not match.")

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                "https://api.notion.com/v1/oauth/token",
                json={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                headers={
                    "Authorization": f"Basic {encoded_client_id_secret}",
                    "Content-Type": "application/json",
                },
            ),
            delete_key_redis(f"notion_state:{org_id}:{user_id}"),
        )

    token_data = response.json()
    await add_key_value_redis(
        f"notion_credentials:{org_id}:{user_id}",
        json.dumps(token_data),
        expire=600,
    )

    # Close the popup
    return HTMLResponse(
        content="""
        <html><script>window.close();</script></html>
        """
    )


# --- Step 3: Retrieve Credentials ---
async def get_notion_credentials(user_id, org_id):
    credentials = await get_value_redis(f"notion_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")

    credentials = json.loads(credentials)
    await delete_key_redis(f"notion_credentials:{org_id}:{user_id}")
    return credentials


# --- Utility functions for Integration Items ---
def _recursive_dict_search(data, target_key):
    if target_key in data:
        return data[target_key]

    for value in data.values():
        if isinstance(value, dict):
            result = _recursive_dict_search(value, target_key)
            if result is not None:
                return result
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    result = _recursive_dict_search(item, target_key)
                    if result is not None:
                        return result
    return None


def create_integration_item_metadata_object(response_json: dict) -> IntegrationItem:
    name = _recursive_dict_search(response_json.get("properties", {}), "content")
    parent_type = (
        "" if response_json["parent"]["type"] is None else response_json["parent"]["type"]
    )

    parent_id = (
        None if response_json["parent"]["type"] == "workspace" else response_json["parent"][parent_type]
    )

    if not name:
        name = _recursive_dict_search(response_json, "content") or "multi_select"

    name = response_json["object"] + " " + name

    return IntegrationItem(
        id=response_json["id"],
        type=response_json["object"],
        name=name,
        creation_time=response_json["created_time"],
        last_modified_time=response_json["last_edited_time"],
        parent_id=parent_id,
    )


# --- Step 4: Fetch items from Notion (optional demo) ---
async def get_items_notion(credentials) -> list[IntegrationItem]:
    credentials = json.loads(credentials)
    response = requests.post(
        "https://api.notion.com/v1/search",
        headers={
            "Authorization": f'Bearer {credentials.get("access_token")}',
            "Notion-Version": "2022-06-28",
        },
    )

    items = []
    if response.status_code == 200:
        results = response.json().get("results", [])
        for result in results:
            items.append(create_integration_item_metadata_object(result))
        print(items)

    return items