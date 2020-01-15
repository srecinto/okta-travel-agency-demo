import os

default_settings = {
    "client_id": os.getenv("OKTA_CLIENT_ID", "Okta Client Id Here"),
    "issuer": os.getenv("OKTA_ISSUER", "Okta Auth Server Issuer Here"),
    "app_config": os.getenv("SITE_APP_CONFIG", "./well-known/default-settings"),
    "okta_org_name": os.getenv("OKTA_ORG_URL", "Okta Org URL Here"),
    "redirect_uri": os.getenv("OKTA_OIDC_REDIRECT_URI", "Okta OIDC Redirect URI Here"),
    "settings": {
        "app_base_url": os.getenv("APP_BASE_URL", "/"),
        "app_logo": os.getenv("APP_LOGO", "/images/logo_light_blue.png"),
        "app_favicon": os.getenv("APP_FAVICON", "/images/favicon.ico"),
        "app_banner_img_1": os.getenv("APP_BANNER_1", "images/corporate-1-slider-slide-1.jpg"),
        "app_banner_img_2": os.getenv("APP_BANNER_2", "images/corporate-1-slider-slide-2.jpg"),
        "app_banner_img_3": os.getenv("APP_BANNER_3", "images/section-image-4.jpg"),
        "app_banner_img_4": os.getenv("APP_BANNER_4", "images/page-services-banner.jpg"),
        "app_testimonial_1": os.getenv("APP_TESTIMONIAL_1", "images/testimonial-1.jpg"),
        "app_testimonial_2": os.getenv("APP_TESTIMONIAL_2", "images/testimonial-2.jpg"),
        "app_thumb_1": os.getenv("APP_THUMB_1", "images/blog-thumb-1.jpg"),
        "app_thumb_2": os.getenv("APP_THUMB_2", "images/blog-thumb-2.jpg"),
        "app_thumb_3": os.getenv("APP_THUMB_3", "images/blog-thumb-3.jpg"),
        "app_thumb_4": os.getenv("APP_THUMB_4", "images/blog-thumb-4.jpg"),
        "app_gallery_1": os.getenv("APP_GALLERY_1", "images/gallery-1.jpg"),
        "app_gallery_2": os.getenv("APP_GALLERY_2", "images/gallery-2.jpg"),
        "app_gallery_3": os.getenv("APP_GALLERY_3", "images/gallery-3.jpg"),
        "app_gallery_4": os.getenv("APP_GALLERY_4", "images/gallery-4.jpg"),
        "app_gallery_5": os.getenv("APP_GALLERY_5", "images/gallery-5.jpg"),
        "app_gallery_6": os.getenv("APP_GALLERY_6", "images/gallery-6.jpg"),

    },
    "client_secret": os.getenv("OKTA_CLIENT_SECRET", "Okta Client Secret Here"),
    "okta_api_token": os.getenv("OKTA_API_TOKEN", "Okta API Token Here"),
    "app_secret_key": os.getenv("SECRET_KEY", "Some Random Generated GUID")
}



