from app.proto import output_pb2, personalInfo_pb2
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
    "ao": "🇦🇴 Angola",
    "bf": "🇧🇫 Burkina Faso",
    "bi": "🇧🇮 Burundi",
    "bj": "🇧🇯 Benin",
    "bw": "🇧🇼 Botswana",
    "cd": "🇨🇩 Democratic Republic of the Congo",
    "cf": "🇨🇫 Central African Republic",
    "cg": "🇨🇬 Republic of the Congo",
    "ci": "🇨🇮 Ivory Coast",
    "cm": "🇨🇲 Cameroon",
    "cv": "🇨🇻 Cape Verde",
    "dj": "🇩🇯 Djibouti",
    "dz": "🇩🇿 Algeria",
    "eg": "🇪🇬 Egypt",
    "eh": "🇪🇭 Western Sahara",
    "er": "🇪🇷 Eritrea",
    "et": "🇪🇹 Ethiopia",
    "ga": "🇬🇦 Gabon",
    "gh": "🇬🇭 Ghana",
    "gm": "🇬🇲 Gambia",
    "gn": "🇬🇳 Guinea",
    "gq": "🇬🇶 Equatorial Guinea",
    "gw": "🇬🇼 Guinea-Bissau",
    "ke": "🇰🇪 Kenya",
    "km": "🇰🇲 Comoros",
    "lr": "🇱🇷 Liberia",
    "ls": "🇱🇸 Lesotho",
    "ly": "🇱🇾 Libya",
    "ma": "🇲🇦 Morocco",
    "mg": "🇲🇬 Madagascar",
    "ml": "🇲🇱 Mali",
    "mr": "🇲🇷 Mauritania",
    "mu": "🇲🇺 Mauritius",
    "mw": "🇲🇼 Malawi",
    "mz": "🇲🇿 Mozambique",
    "na": "🇳🇦 Namibia",
    "ne": "🇳🇪 Niger",
    "ng": "🇳🇬 Nigeria",
    "rw": "🇷🇼 Rwanda",
    "sc": "🇸🇨 Seychelles",
    "sd": "🇸🇩 Sudan",
    "sl": "🇸🇱 Sierra Leone",
    "sn": "🇸🇳 Senegal",
    "so": "🇸🇴 Somalia",
    "ss": "🇸🇸 South Sudan",
    "sz": "🇸🇿 Eswatini",
    "td": "🇹🇩 Chad",
    "tg": "🇹🇬 Togo",
    "tn": "🇹🇳 Tunisia",
    "tz": "🇹🇿 Tanzania",
    "ug": "🇺🇬 Uganda",
    "za": "🇿🇦 South Africa",
    "zm": "🇿🇲 Zambia",
    "zw": "🇿🇼 Zimbabwe",

    # The Americas
    "ag": "🇦🇬 Antigua and Barbuda",
    "ai": "🇦🇮 Anguilla",
    "ar": "🇦🇷 Argentina",
    "aw": "🇦🇼 Aruba",
    "bb": "🇧🇧 Barbados",
    "bl": "🇧🇱 Saint Barthélemy",
    "bm": "🇧🇲 Bermuda",
    "bo": "🇧🇴 Bolivia",
    "bq": "🇧🇶 Caribbean Netherlands",
    "br": "🇧🇷 Brazil",
    "bs": "🇧🇸 Bahamas",
    "bz": "🇧🇿 Belize",
    "ca": "🇨🇦 Canada",
    "cl": "🇨🇱 Chile",
    "co": "🇨🇴 Colombia",
    "cr": "🇨🇷 Costa Rica",
    "cu": "🇨🇺 Cuba",
    "cw": "🇨🇼 Curaçao",
    "dm": "🇩🇲 Dominica",
    "do": "🇩🇴 Dominican Republic",
    "ec": "🇪🇨 Ecuador",
    "fk": "🇫🇰 Falkland Islands",
    "gd": "🇬🇩 Grenada",
    "gf": "🇬🇫 French Guiana",
    "gp": "🇬🇵 Guadeloupe",
    "gt": "🇬🇹 Guatemala",
    "gy": "🇬🇾 Guyana",
    "hn": "🇭🇳 Honduras",
    "ht": "🇭🇹 Haiti",
    "jm": "🇯🇲 Jamaica",
    "kn": "🇰🇳 Saint Kitts and Nevis",
    "ky": "🇰🇾 Cayman Islands",
    "lc": "🇱🇨 Saint Lucia",
    "mf": "🇲🇫 Saint Martin",
    "mq": "🇲🇶 Martinique",
    "ms": "🇲🇸 Montserrat",
    "mx": "🇲🇽 Mexico",
    "ni": "🇳🇮 Nicaragua",
    "pa": "🇵🇦 Panama",
    "pe": "🇵🇪 Peru",
    "pm": "🇵🇲 Saint Pierre and Miquelon",
    "pr": "🇵🇷 Puerto Rico",
    "py": "🇵🇾 Paraguay",
    "sr": "🇸🇷 Suriname",
    "sv": "🇸🇻 El Salvador",
    "sx": "🇸🇽 Sint Maarten",
    "tc": "🇹🇨 Turks and Caicos Islands",
    "tt": "🇹🇹 Trinidad and Tobago",
    "us": "🇺🇸 United States",
    "uy": "🇺🇾 Uruguay",
    "ve": "🇻🇪 Venezuela",
    "vg": "🇻🇬 British Virgin Islands",
    "vi": "🇻🇮 U.S. Virgin Islands"
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
MONGO_URI = os.getenv("MONGO_URI")
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

def format_response_data(data, region):
    """Format response data to include region flags and prime icons"""
    if isinstance(data, dict):
        # Format region with flag
        if 'region' in data:
            region_code = data['region'].lower()
            flag = REGION_FLAGS.get(region_code, "")
            if flag:
                data['region'] = f"{data['region']} {flag}"
        
        # Format prime level with icon
        if 'primeLevel' in data and isinstance(data['primeLevel'], dict):
            prime_level = data['primeLevel'].get('primeLevel')
            if prime_level and prime_level in PRIME_ICONS:
                data['primeLevel']['primeLevel'] = f"{prime_level} {PRIME_ICONS[prime_level]}"
        
        # Recursively format nested dictionaries
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

        # Try regions in priority order
        # Try regions in priority order; ensure we include 'us' so tokens in DB are used
        region_priority = ["bd", "pk", "ind", "us", "na", "sg", "ru", "br", "vn", "tw", "id", "th", "me", "eu"]
        successful_region = None
        
        for region in region_priority:
            token = tokens.get(region)
            if not token:
                continue
                
            try:
                print(f"Trying region: {region} with token ending in ...{token[-10:] if len(token)>10 else token}")
                # Prepare request data
                server_url = get_url(region)
                headers = build_headers(token)
                encoded_result = await json_to_proto(json_data, output_pb2.PlayerInfoByLokesh())
                payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
                
                # Make API request
                async with httpx.AsyncClient(verify=False) as client:
                    response = await client.post(server_url + endpoint, data=payload, headers=headers)
                    print(f"Region {region} Response Status: {response.status_code}")
                    response.raise_for_status()
                    
                    # Decode response
                    message = decode_protobuf(response.content, personalInfo_pb2.PersonalInfoByLokesh)
                    
                    if hasattr(message, 'developer_info'):
                        # Create developer info object
                        dev_info = personalInfo_pb2.DeveloperInfo()
                        dev_info.developer_name = "Sukh Daku !"  
                        dev_info.portfolio = "https://sukhdaku.qzz.io/"
                        dev_info.github = "@sukhdaku"
                        dev_info.signature = "Sukh Daku — Always learning 💻 Full-stack Developer "
                        dev_info.do_not_remove_credits = True
                        
                        # Assign to message
                        message.developer_info.CopyFrom(dev_info)
                    
                    # Convert to JSON and format with flags/icons
                    json_data = json.loads(json_format.MessageToJson(message))
                    successful_region = region
                    return format_response_data(json_data, successful_region)
                    
            except Exception as e:
                print(f"Region {region} failed with error: {str(e)}")
                if hasattr(e, 'response') and e.response is not None:
                     print(f"Server response content: {e.response.text}")
                # Continue to next region if current one fails
                continue
        
        # If all regions failed
        return {
            "error": "All regions failed",
            "message": "Unable to fetch account information"
        }

    except Exception as e:
        return {
            "error": "Failed to get account info",
            "reason": str(e)
        }
