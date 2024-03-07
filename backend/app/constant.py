import os

IMPORTANT_DATES = "Important dates"
FLAT_RATE = "flat rate"
ADDRESS_LINE_1 = "address line 1"
ADDRESS_LINE_2 = "address line 2"
ADDRESS_LINE_3 = "address line 3"
ZIP_CODE = "zip code"
ALT_PHONE_NUMBER = "alt phone number"
SECTION_1 = "section 1"
SECTION_2 = "section 2"
SECTION_3 = "section 3"
SECTION_4 = "section 4"
SECTION_5 = "section 5"

IMG_URL = f'https://{os.getenv("AWS_S3_CUSTOM_DOMAIN")}/'
LOGO_URL = f'https://{os.getenv("AWS_S3_CUSTOM_DOMAIN")}/images/handmerch.svg'
BACKEND_URL = os.getenv("BACKEND_URL")
REDIRECT_URL = os.getenv("REDIRECT_URL")
