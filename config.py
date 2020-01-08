import os


default_settings = {
    "client_id": os.getenv("OKTA_CLIENT_ID", "Okta Client Id Here"),
    "issuer": os.getenv("OKTA_ISSUER", "Okta Auth Server Issuer Here"),
    "app_config": os.getenv("SITE_APP_CONFIG", "./well-known/default-settings"),
    "okta_org_name": os.getenv("OKTA_ORG_URL", "Okta Org URL Here"),
    "redirect_uri": os.getenv("OKTA_OIDC_REDIRECT_URI", "Okta OIDC Redirect URI Here"),
    "settings": {
        "app_base_url": os.getenv("APP_BASE_URL", "/"),
    },
    "client_secret": os.getenv("OKTA_CLIENT_SECRET", "Okta Client Secret Here"),
    "okta_api_token": os.getenv("OKTA_API_TOKEN", "Okta API Token Here"),
    "app_secret_key": os.getenv("SECRET_KEY", "Some Random Generated GUID")
}



