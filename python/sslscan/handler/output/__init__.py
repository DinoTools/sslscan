from sslscan import Color, config as g_config

def get_cipher_color(cipher, rules_name, config=None, color=None):
    if config == None:
        config = g_config
    if color == None:
        color = Color(config)

    rules = rating_rules.get(config.get_value("rating"))
    if rules == None:
        return ""

    rules = rules.get("rules", {})
    color_rules = rules.get(rules_name, [])
    for f in color_rules:
        c = f(cipher)
        if c is not None:
            return getattr(color, c)
    return ""

def get_cipher_bits_color(cipher, config=None, color=None):
    return get_cipher_color(cipher, "cipher_bits", config, color)

def get_cipher_method_name_color(cipher, config=None, color=None):
    return get_cipher_color(cipher, "cipher_method_name", config, color)

def get_cipher_name_color(cipher, config=None, color=None):
    return get_cipher_color(cipher, "cipher_name", config, color)

rating_rules = {}
rating_rules["ssllabs-2009e"] = {
    "name": "SSL Labs Rating 2009e",
    "description": """Rating derived from SSL Server Rating Guide version 2009e (21 January 2014) by Qualys SSL Labs http://www.ssllabs.com""",
    "rules": {
        "cipher_bits": [
            lambda cipher: "DANGER" if cipher.get("bits") < 128 else None,
            lambda cipher: "WARNING" if cipher.get("bits") < 256 else None,
            lambda cipher: "OK" if cipher.get("bits", 0) >= 256 else None
        ],
        "cipher_method_name": [
            lambda cipher: "DANGER" if cipher.get("method.name") == "SSLv2" else None,
            lambda cipher: "OK" if cipher.get("method.name") == "TLS12" else None
        ]
    }
}

