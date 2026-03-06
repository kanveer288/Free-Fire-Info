from proto import output_pb2, personalInfo_pb2
import httpx
import json
import time
from google.protobuf import json_format, message
from Crypto.Cipher import AES
import base64
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

# Constants
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASE_VERSION = "OB52"

# Region to flag mapping
REGION_FLAGS = {
    # Africa
    "Angola": "🇦🇴", "Burkina Faso": "🇧🇫", "Burundi": "🇧🇮", "Benin": "🇧🇯", "Botswana": "🇧🇼", "Democratic Republic of the Congo": "🇨🇩", "Central African Republic": "🇨🇫", "Republic of the Congo": "🇨🇬", 
    "Ivory Coast": "🇨🇮", "Cameroon": "🇨🇲", "Cape Verde": "🇨🇻", "Djibouti": "🇩🇯", "Algeria": "🇩🇿", "Egypt": "🇪🇬", "Western Sahara": "🇪🇭", "Eritrea": "🇪🇷", 
    "Ethiopia": "🇪🇹", "Gabon": "🇬🇦", "Ghana": "🇬🇭", "Gambia": "🇬🇲", "Guinea": "🇬🇳", "Equatorial Guinea": "🇬🇶", "Guinea-Bissau": "🇬🇼", "Kenya": "🇰🇪", 
    "Comoros": "🇰🇲", "Liberia": "🇱🇷", "Lesotho": "🇱🇸", "Libya": "🇱🇾", "Morocco": "🇲🇦", "Madagascar": "🇲🇬", "Mali": "🇲🇱", "Mauritania": "🇲🇷", 
    "Mauritius": "🇲🇺", "Malawi": "🇲🇼", "Mozambique": "🇲🇿", "Namibia": "🇳🇦", "Niger": "🇳🇪", "Nigeria": "🇳🇬", "Rwanda": "🇷🇼", "Seychelles": "🇸🇨", 
    "Sudan": "🇸🇩", "Sierra Leone": "🇸🇱", "Senegal": "🇸🇳", "Somalia": "🇸🇴", "South Sudan": "🇸🇸", "Eswatini": "🇸🇿", "Chad": "🇹🇩", "Togo": "🇹🇬", 
    "Tunisia": "🇹🇳", "Tanzania": "🇹🇿", "Uganda": "🇺🇬", "South Africa": "🇿🇦", "Zambia": "🇿🇲", "Zimbabwe": "🇿🇼",
    
    # The Americas
    "Antigua and Barbuda": "🇦🇬", "Anguilla": "🇦🇮", "Argentina": "🇦🇷", "Aruba": "AW", "Barbados": "🇧🇧", "Saint Barthélemy": "🇧🇱", "Bermuda": "🇧🇲", "Bolivia": "🇧🇴", 
    "Bonaire": "🇧🇶", "Brazil": "🇧🇷", "Bahamas": "🇧🇸", "Belize": "🇧🇿", "Canada": "🇨🇦", "Chile": "🇨🇱", "Colombia": "🇨🇴", "Costa Rica": "🇨🇷", 
    "Cuba": "🇨🇺", "Curaçao": "🇨🇼", "Dominica": "🇩🇲", "Dominican Republic": "🇩🇴", "Ecuador": "🇪🇨", "Falkland Islands": "🇫🇰", "Grenada": "🇬🇩", "French Guiana": "🇬🇫", 
    "Guadeloupe": "🇬🇵", "Guatemala": "🇬🇹", "Guyana": "🇬🇾", "Honduras": "🇭🇳", "Haiti": "🇭🇹", "Jamaica": "🇯🇲", "Saint Kitts and Nevis": "🇰🇳", "Cayman Islands": "🇰🇾", 
    "Saint Lucia": "🇱🇨", "Saint Martin": "🇲🇫", "Martinique": "🇲🇶", "Montserrat": "🇲🇸", "Mexico": "🇲🇽", "Nicaragua": "🇳🇮", "Panama": "🇵🇦", "Peru": "🇵🇪", 
    "Saint Pierre and Miquelon": "🇵🇲", "Puerto Rico": "🇵🇷", "Paraguay": "🇵🇾", "Suriname": "🇸🇷", "El Salvador": "🇸🇻", "Sint Maarten": "🇸🇽", "Turks and Caicos Islands": "🇹🇨", "Trinidad and Tobago": "🇹🇹", 
    "United States": "🇺🇸", "Uruguay": "🇺🇾", "Venezuela": "🇻🇪", "British Virgin Islands": "🇻🇬", "United States Virgin Islands": "🇻🇮",
    
    # Asia & The Middle East
    "United Arab Emirates": "🇦🇪", "Afghanistan": "🇦🇫", "Azerbaijan": "🇦🇿", "Bangladesh": "🇧🇩", "Bahrain": "🇧🇭", "Brunei": "🇧🇳", "Bhutan": "🇧🇹", "China": "🇨🇳", 
    "Hong Kong": "🇭🇰", "Indonesia": "🇮🇩", "Israel": "🇮🇱", "India": "🇮🇳", "India_alt": "🇮🇳", "Iraq": "🇮🇶", "Iran": "🇮🇷", "Jordan": "🇯🇴", 
    "Japan": "🇯🇵", "Kyrgyzstan": "🇰🇬", "Cambodia": "🇰🇭", "North Korea": "🇰🇵", "South Korea": "🇰🇷", "Kuwait": "🇰🇼", "Kazakhstan": "🇰🇿", "Laos": "🇱🇦", 
    "Lebanon": "🇱🇧", "Sri Lanka": "🇱🇰", "Myanmar": "🇲🇲", "Mongolia": "🇲🇳", "Macau": "🇲🇴", "Maldives": "🇲🇻", "Malaysia": "🇲🇾", "Nepal": "🇳🇵", 
    "Oman": "🇴🇲", "Philippines": "🇵🇭", "Pakistan": "🇵🇰", "Palestine": "🇵🇸", "Qatar": "🇶🇦", "Russia": "🇷🇺", "Saudi Arabia": "🇸🇦", "Singapore": "🇸🇬", 
    "Syria": "🇸🇾", "Thailand": "🇹🇭", "Tajikistan": "🇹🇯", "Timor-Leste": "🇹🇱", "Turkmenistan": "🇹🇲", "Turkey": "🇹🇷", "Taiwan": "🇹🇼", "Uzbekistan": "🇺🇿", 
    "Vietnam": "🇻🇳", "Yemen": "🇾🇪",
    
    # Europe
    "Andorra": "🇦🇩", "Albania": "🇦🇱", "Armenia": "🇦🇲", "Austria": "🇦🇹", "Bosnia and Herzegovina": "🇧🇦", "Belgium": "🇧🇪", "Bulgaria": "🇧🇬", "Belarus": "🇧🇾", 
    "Switzerland": "🇨🇭", "Sark": "🇨🇶", "Cyprus": "🇨🇾", "Czech Republic": "🇨🇿", "Germany": "🇩🇪", "Denmark": "🇩🇰", "Ceuta & Melilla": "🇪🇦", "Estonia": "🇪🇪", 
    "Spain": "🇪🇸", "European Union": "🇪🇺", "Finland": "🇫🇮", "France": "🇫🇷", "United Kingdom": "🇬🇧", "Georgia": "🇬🇪", "Guernsey": "🇬🇬", "Gibraltar": "🇬🇮", 
    "Greece": "🇬🇷", "Croatia": "🇭🇷", "Hungary": "🇭🇺", "Ireland": "🇮🇪", "Isle of Man": "🇮🇲", "Iceland": "🇮🇸", "Italy": "🇮🇹", "Jersey": "🇯🇪", 
    "Liechtenstein": "🇱🇮", "Lithuania": "🇱🇹", "Luxembourg": "🇱🇺", "Latvia": "🇱🇻", "Monaco": "🇲🇨", "Moldova": "🇲🇩", "Montenegro": "🇲🇪", "North Macedonia": "🇲🇰", 
    "Malta": "🇲🇹", "Netherlands": "🇳🇱", "Norway": "🇳🇴", "Poland": "🇵🇱", "Portugal": "🇵🇹", "Romania": "🇷🇴", "Serbia": "🇷🇸", "Sweden": "🇸🇪", 
    "Slovenia": "🇸🇮", "Slovakia": "🇸🇰", "San Marino": "🇸🇲", "Ukraine": "🇺🇦", "Vatican City": "🇻🇦", "Kosovo": "🇽🇰", "England": "🏴", 
    "Scotland": "🏴", "Wales": "🏴",
    
    # Oceania, Island Nations & Territories
    "Ascension Island": "🇦🇨", "Antarctica": "🇦🇶", "American Samoa": "🇦🇸", "Australia": "🇦🇺", "Åland Islands": "🇦🇽", "Bouvet Island": "🇧🇻", "Cocos Islands": "🇨🇨", "Cook Islands": "🇨🇰", 
    "Clipperton Island": "🇨🇵", "Christmas Island": "🇨🇽", "Diego Garcia": "🇩🇬", "Fiji": "🇫🇯", "Micronesia": "🇫🇲", "Greenland": "🇬🇱", "South Georgia and the South Sandwich Islands": "🇬🇸", "Guam": "🇬🇺", 
    "Heard Island and McDonald Islands": "🇭🇲", "Canary Islands": "🇮🇨", "British Indian Ocean Territory": "🇮🇴", "Kiribati": "🇰🇮", "Marshall Islands": "🇲🇭", "Northern Mariana Islands": "🇲🇵", "New Caledonia": "🇳🇨", "Norfolk Island": "🇳🇫", 
    "Nauru": "🇳🇷", "Niue": "🇳🇺", "New Zealand": "🇳🇿", "French Polynesia": "🇵🇫", "Papua New Guinea": "🇵🇬", "Pitcairn Islands": "🇵🇳", "Palau": "🇵🇼", "Réunion": "🇷🇪", 
    "Solomon Islands": "🇸🇧", "Saint Helena": "🇸🇭", "Svalbard and Jan Mayen": "🇸🇯", "São Tomé and Príncipe": "🇸🇹", "Tristan da Cunha": "🇹🇦", "French Southern Territories": "🇹🇫", "Tokelau": "🇹🇰", "Tonga": "🇹🇴", 
    "Tuvalu": "🇹🇻", "United States Minor Outlying Islands": "🇺🇲", "Saint Vincent and the Grenadines": "🇻🇨", "Vanuatu": "🇻🇺", "Wallis and Futuna": "🇼🇫", "Samoa": "🇼🇸", "Mayotte": "🇾🇹"
}

# Prime level to Discord emoji mapping
PRIME_ICONS = {
    1: "<:prime_1:1432065617246294208>",
    2: "<:prime_2:1432065635608690778>",
    3: "<:prime_3:1432065651530272928>",
    4: "<:prime_4:1432065675521691758>",
    5: "<:prime_5:1432065689597771887>",
    6: "<:prime_6:1432065707863965758>",
    7: "<:prime_7:1432065724184264704>",
    8: "<:prime_8:1432065741980565594>"
}

# MongoDB connection
MONGO_URI = "mongodb+srv://NullSociety:bo2c0rs0LgDCh4Fc@xpert.8w1vywl.mongodb.net/?appName=xpert"
client = MongoClient(MONGO_URI)
db = client.info
tokens_collection = db.tokens

async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    """Convert JSON data to protobuf bytes"""
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def pad(text: bytes) -> bytes:
    """Add PKCS7 padding to text"""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using AES-CBC"""
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    return aes.encrypt(padded_plaintext)

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    """Decode protobuf data"""
    message_instance = message_type()
    message_instance.ParseFromString(encoded_data)
    return message_instance

def get_jwt_tokens():
    """Get JWT tokens from database for allowed regions"""
    allowed_regions = {"bd", "pk", "ind", "us", "na", "sg", "ru", "br", "vn", "tw", "id", "th", "me", "eu"}
    tokens_cursor = tokens_collection.find({"region": {"$in": list(allowed_regions)}})
    
    tokens = {}
    for doc in tokens_cursor:
        region = doc.get("region")
        token = doc.get("token")
        if region and token:
            tokens[region] = token
            print(f"Loaded token for region: {region}") # Debug print
    return tokens

def get_url(region):
    if region == "ind":
        return "https://client.ind.freefiremobile.com"
    elif region in {"br", "us", "sac", "na"}:
        return "https://client.us.freefiremobile.com"
    else:
        return "https://clientbp.common.ggbluefox.com"

def build_headers(token):
    return {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; A063 Build/TKQ1.221220.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': f"Bearer {token}",
        'X-Unity-Version': "2022.3.47f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASE_VERSION
    }

def format_value(value, region):
    if isinstance(value, dict):
        return format_response_data(value, region)
    elif isinstance(value, list):
         return [format_value(item, region) for item in value]
    return value

# Mapping for 2-letter codes to full names for lookup
ISO_MAP = {
    "in": "India", "ind": "India", "pk": "Pakistan", "bd": "Bangladesh", "br": "Brazil", "us": "United States",
    "na": "United States", "sg": "Singapore", "ru": "Russia", "vn": "Vietnam", "tw": "Taiwan", "id": "Indonesia",
    "th": "Thailand", "me": "Middle East", "eu": "European Union", "af": "Afghanistan", "dz": "Algeria",
    "as": "American Samoa", "ad": "Andorra", "ao": "Angola", "ai": "Anguilla", "aq": "Antarctica",
    "ag": "Antigua and Barbuda", "ar": "Argentina", "am": "Armenia", "aw": "Aruba", "au": "Australia",
    "at": "Austria", "az": "Azerbaijan", "bs": "Bahamas", "bh": "Bahrain", "bb": "Barbados", "by": "Belarus",
    "be": "Belgium", "bz": "Belize", "bj": "Benin", "bm": "Bermuda", "bt": "Bhutan", "bo": "Bolivia",
    "ba": "Bosnia and Herzegovina", "bw": "Botswana", "bv": "Bouvet Island", "bn": "Brunei", "bg": "Bulgaria",
    "bf": "Burkina Faso", "bi": "Burundi", "kh": "Cambodia", "cm": "Cameroon", "ca": "Canada", "cv": "Cape Verde",
    "ky": "Cayman Islands", "cf": "Central African Republic", "td": "Chad", "cl": "Chile", "cn": "China",
    "cx": "Christmas Island", "cc": "Cocos Islands", "co": "Colombia", "km": "Comoros", "cg": "Republic of the Congo",
    "cd": "Democratic Republic of the Congo", "ck": "Cook Islands", "cr": "Costa Rica", "ci": "Ivory Coast",
    "hr": "Croatia", "cu": "Cuba", "cy": "Cyprus", "cz": "Czech Republic", "dk": "Denmark", "dj": "Djibouti",
    "dm": "Dominica", "do": "Dominican Republic", "ec": "Ecuador", "eg": "Egypt", "sv": "El Salvador",
    "gq": "Equatorial Guinea", "er": "Eritrea", "ee": "Estonia", "et": "Ethiopia", "fk": "Falkland Islands",
    "fo": "Faroe Islands", "fj": "Fiji", "fi": "Finland", "fr": "France", "gf": "French Guiana",
    "pf": "French Polynesia", "tf": "French Southern Territories", "ga": "Gabon", "gm": "Gambia",
    "ge": "Georgia", "de": "Germany", "gh": "Ghana", "gi": "Gibraltar", "gr": "Greece", "gl": "Greenland",
    "gd": "Grenada", "gp": "Guadeloupe", "gu": "Guam", "gt": "Guatemala", "gg": "Guernsey", "gn": "Guinea",
    "gw": "Guinea-Bissau", "gy": "Guyana", "ht": "Haiti", "hm": "Heard Island and McDonald Islands",
    "va": "Vatican City", "hn": "Honduras", "hk": "Hong Kong", "hu": "Hungary", "is": "Iceland",
    "iq": "Iraq", "ie": "Ireland", "im": "Isle of Man", "il": "Israel", "it": "Italy", "jm": "Jamaica",
    "jp": "Japan", "je": "Jersey", "jo": "Jordan", "kz": "Kazakhstan", "ke": "Kenya", "ki": "Kiribati",
    "kp": "North Korea", "kr": "South Korea", "kw": "Kuwait", "kg": "Kyrgyzstan", "la": "Laos", "lv": "Latvia",
    "lb": "Lebanon", "ls": "Lesotho", "lr": "Liberia", "ly": "Libya", "li": "Liechtenstein", "lt": "Lithuania",
    "lu": "Luxembourg", "mo": "Macau", "mk": "North Macedonia", "mg": "Madagascar", "mw": "Malawi",
    "my": "Malaysia", "mv": "Maldives", "ml": "Mali", "mt": "Malta", "mh": "Marshall Islands", "mq": "Martinique",
    "mr": "Mauritania", "mu": "Mauritius", "yt": "Mayotte", "mx": "Mexico", "fm": "Micronesia", "md": "Moldova",
    "mc": "Monaco", "mn": "Mongolia", "me": "Montenegro", "ms": "Montserrat", "ma": "Morocco", "mz": "Mozambique",
    "mm": "Myanmar", "na": "Namibia", "nr": "Nauru", "np": "Nepal", "nl": "Netherlands", "nc": "New Caledonia",
    "nz": "New Zealand", "ni": "Nicaragua", "ne": "Niger", "ng": "Nigeria", "nu": "Niue", "nf": "Norfolk Island",
    "mp": "Northern Mariana Islands", "no": "Norway", "om": "Oman", "pw": "Palau", "ps": "Palestine",
    "pa": "Panama", "pg": "Papua New Guinea", "py": "Paraguay", "pe": "Peru", "ph": "Philippines",
    "pn": "Pitcairn Islands", "pl": "Poland", "pt": "Portugal", "pr": "Puerto Rico", "qa": "Qatar",
    "re": "Réunion", "ro": "Romania", "rs": "Serbia", "rw": "Rwanda", "bl": "Saint Barthélemy",
    "sh": "Saint Helena", "kn": "Saint Kitts and Nevis", "lc": "Saint Lucia", "mf": "Saint Martin",
    "pm": "Saint Pierre and Miquelon", "vc": "Saint Vincent and the Grenadines", "ws": "Samoa",
    "sm": "San Marino", "st": "São Tomé and Príncipe", "sa": "Saudi Arabia", "sn": "Senegal",
    "sc": "Seychelles", "sl": "Sierra Leone", "sk": "Slovakia", "si": "Slovenia", "sb": "Solomon Islands",
    "so": "Somalia", "za": "South Africa", "gs": "South Georgia and the South Sandwich Islands",
    "es": "Spain", "lk": "Sri Lanka", "sd": "Sudan", "sr": "Suriname", "sj": "Svalbard and Jan Mayen",
    "sz": "Eswatini", "se": "Sweden", "ch": "Switzerland", "sy": "Syria", "tj": "Tajikistan",
    "tz": "Tanzania", "tl": "Timor-Leste", "tg": "Togo", "tk": "Tokelau", "to": "Tonga",
    "tt": "Trinidad and Tobago", "tn": "Tunisia", "tr": "Turkey", "tm": "Turkmenistan",
    "tc": "Turks and Caicos Islands", "tv": "Tuvalu", "ug": "Uganda", "ua": "Ukraine",
    "ae": "United Arab Emirates", "gb": "United Kingdom", "um": "United States Minor Outlying Islands",
    "uy": "Uruguay", "uz": "Uzbekistan", "vu": "Vanuatu", "ve": "Venezuela", "ye": "Yemen", "zm": "Zambia",
    "zw": "Zimbabwe", "eng": "England", "sct": "Scotland", "wls": "Wales"
}

def format_response_data(data, region):
    """Format response data to include region flags and prime icons recursively"""
    if isinstance(data, dict):
        # Format region with flag
        if 'region' in data:
            region_code = data['region'].lower()
            # Special check for 'pk' or others if needed, typically just 2 chars
            iso_code = region_code[:3].lower() if region_code.startswith('ind') else region_code[:2].lower()
            country_name = ISO_MAP.get(iso_code, "")
            flag = REGION_FLAGS.get(country_name, "")
            if flag:
                 # Ensure we don't double-add if it's already there
                 if flag not in data['region']:
                    data['region'] = f"{data['region']} {flag}"
        
        # Format prime level with icon
        if 'primeLevel' in data and isinstance(data['primeLevel'], dict):
            prime_level = data['primeLevel'].get('primeLevel')
            if prime_level:
                try: 
                    # Assuming prime_level is number or string number
                    pl_int = int(str(prime_level).split()[0])
                    if pl_int in PRIME_ICONS:
                         data['primeLevel']['primeLevel'] = f"{pl_int} {PRIME_ICONS[pl_int]}"
                except:
                    pass

        # Recursively format
        for key, value in data.items():
            if isinstance(value, dict):
                data[key] = format_response_data(value, region)
            elif isinstance(value, list):
                data[key] = [format_response_data(item, region) if isinstance(item, dict) else item for item in value]

    return data

async def GetAccountInformation(ID, UNKNOWN_ID, endpoint):
    """Get account information from Free Fire API"""
    try:
        # Create JSON payload
        json_data = json.dumps({
            "a": ID,
            "b": UNKNOWN_ID
        })
        
        # Get tokens from database
        tokens = get_jwt_tokens()
        if not tokens:
            print("No tokens found in database!")
            return {
                "error": "No tokens found in database",
                "message": "Service temporarily unavailable"
            }

        region_priority = ["bd", "pk", "ind", "us", "na", "sg", "ru", "br", "vn", "tw", "id", "th", "me", "eu"]
        successful_region = None
        
        for region in region_priority:
            token = tokens.get(region)
            if not token:
                continue
                
            try:
                print(f"Trying region: {region} with token ending in ...{token[-10:] if len(token)>10 else token}")
                server_url = get_url(region)
                headers = build_headers(token)
                encoded_result = await json_to_proto(json_data, output_pb2.PlayerInfoByLokesh())
                payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
                
                async with httpx.AsyncClient(verify=False) as client:
                    response = await client.post(server_url + endpoint, data=payload, headers=headers)
                    print(f"Region {region} Response Status: {response.status_code}")
                    response.raise_for_status()
                    
                    message = decode_protobuf(response.content, personalInfo_pb2.PersonalInfoByLokesh)
                    
                    if hasattr(message, 'developer_info'):
                        dev_info = personalInfo_pb2.DeveloperInfo()
                        dev_info.developer_name = "Sukh Daku !"  
                        dev_info.portfolio = "https://sukhdaku.qzz.io/"
                        dev_info.github = "@sukhdaku"
                        dev_info.signature = "Sukh Daku — Always learning 💻 Full-stack Developer "
                        dev_info.do_not_remove_credits = True
                        message.developer_info.CopyFrom(dev_info)
                    
                    # Convert to JSON
                    raw_json = json.loads(json_format.MessageToJson(message))
                    formatted_data = format_response_data(raw_json, region)
                    
                    # Restructure Response to match user requirement
                    # Flatten the response: extract keys from top level and move them out?
                    # Looking at user's "to" example:
                    # It has: playerData, profileInfo, guildInfo, guildOwnerInfo, petInfo, socialInfo, diamondCostRes, creditScoreInfo, developerInfo
                    # These are exactly the fields in PersonalInfoByLokesh (playerData, profileInfo, etc.)
                    # The "from" example had them nested or ordered differently? 
                    # Actually, the protobuf `PersonalInfoByLokesh` ALREADY has these correct fields.
                    # The user's "from" example order seems alphabetical. The "to" example is just ordered differently or maybe the structure is already correct?
                    # Wait, looking closely at "To" example:
                    # "playerData" is top level. "profileInfo" is top level.
                    # In protobuf definition:
                    # message PersonalInfoByLokesh {
                    #   AccountInfoBasic player_data = 1;
                    #   AvatarProfile profile_info = 2;
                    # ... }
                    # `json_format.MessageToJson` uses camelCase by default (e.g. player_data -> playerData).
                    # So the structure should be correct already.
                    # HOWEVER, user might be complaining about some specific nesting or missing fields or just order.
                    # Checking the "from" example again. It is alphabetic.
                    # Checking the "to" example. It is custom ordered.
                    # JSON keys are unordered by definition, but some clients care.
                    # Python dicts preserve insertion order (3.7+).
                    # So I will explicitly construct the dictionary in the desired order.
                    
                    ordered_response = {}
                    key_order = [
                        "playerData", "profileInfo", "guildInfo", "guildOwnerInfo", 
                        "petInfo", "socialInfo", "diamondCostRes", "creditScoreInfo", "developerInfo"
                    ]
                    
                    for key in key_order:
                        if key in formatted_data:
                            ordered_response[key] = formatted_data[key]
                    
                    # Add any remaining keys
                    for key, value in formatted_data.items():
                        if key not in ordered_response:
                            ordered_response[key] = value

                    return ordered_response
                    
            except Exception as e:
                print(f"Region {region} failed with error: {str(e)}")
                # Continue
                continue
        
        return {
            "error": "All regions failed",
            "message": "Unable to fetch account information"
        }

    except Exception as e:
        return {
            "error": "Failed to get account info",
            "reason": str(e)
        }
