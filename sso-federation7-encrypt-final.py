# filename: lambda_function.py
# runtime: Python 3.12

import os
import time
import json
import base64
import logging
from typing import Dict, List, Any, Optional

import boto3
import botocore
import xml.etree.ElementTree as ET

# --- crypto deps ---
# Requires the 'cryptography' library available in the Lambda runtime (layer or vendored)
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# ========= Configuration (env) =========
DDB_TABLE = os.environ.get("DDB_TABLE")  # required

# NEW: TTL attribute name (defaults to 'ttl' to match your table)
TTL_ATTR_NAME = os.environ.get("TTL_ATTR_NAME", "ttl")
TTL_SECONDS = int(os.environ.get("TTL_SECONDS", "120"))

LOG_SAML_XML = os.environ.get("LOG_SAML_XML", "false").lower() == "true"
LOG_PREVIEW_CHARS = int(os.environ.get("LOG_PREVIEW_CHARS", "800"))
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

USERNAME_PREFIX_TO_STRIP = os.environ.get("USERNAME_PREFIX_TO_STRIP", "")  # e.g., "O365-SSO_"

# Configurable SAML attribute names (defaults chosen to match existing behavior)
FIRST_ATTRIB_NAME = os.environ.get("FIRST_ATTRIB", "MRN")
SECOND_ATTRIB_NAME = os.environ.get("SECOND_ATTRIB", "UID")

# Default to use when SECOND_ATTRIB is empty/not present in SAML
SECOND_ATTRIB_DEFAULT = os.environ.get("SECOND_ATTRIB_DEFAULT", "VVMC_CA_VVMC_H")

# NEW: Secrets Manager public cert name (PEM X.509 certificate holding the public key)
PUBLIC_KEY_SECRET_NAME = os.environ.get("PUBLIC_KEY_SECRET_NAME")

if not DDB_TABLE:
    raise RuntimeError("Environment variable DDB_TABLE is required")
if not PUBLIC_KEY_SECRET_NAME:
    raise RuntimeError("Environment variable PUBLIC_KEY_SECRET_NAME is required for encryption")

# ========= AWS clients/resources =========
ddb_resource = boto3.resource("dynamodb")
table = ddb_resource.Table(DDB_TABLE)
secrets_client = boto3.client("secretsmanager")

# ========= Logging =========
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- TTL attribute name safety guard ---
# Your DynamoDB table is configured with TTL attribute 'ttl' (lowercase).
# If the function is deployed with TTL_ATTR_NAME set to anything else (e.g., 'TTL'),
# override it at runtime so items actually expire.
if TTL_ATTR_NAME != "ttl":
    logger.warning(
        "TTL_ATTR_NAME is '%s' but table TTL attribute is 'ttl'; overriding to 'ttl'.",
        TTL_ATTR_NAME,
    )
    TTL_ATTR_NAME = "ttl"

# ========= Constants =========
NS = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
HASH_NAME = "user_name"  # DynamoDB partition key attribute name

# ========= Public key cache =========
_PUBLIC_KEY_OBJ = None

# ========= Utils =========
def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)

def _safe_preview(text: str, max_len: int = 800) -> str:
    return text if len(text) <= max_len else text[:max_len] + "...(truncated)"

def _maybe_decode_base64(s: str) -> Optional[str]:
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return None

def _normalize_username(raw: str) -> str:
    """
    Returns `raw` unchanged unless USERNAME_PREFIX_TO_STRIP is non-empty
    AND `raw` starts with that exact prefix. Then it strips the prefix.
    Normal users (no matching prefix) are unaffected.
    """
    prefix = USERNAME_PREFIX_TO_STRIP
    if prefix and isinstance(raw, str) and raw.startswith(prefix):
        return raw[len(prefix):]
    return raw

def _parse_saml_attributes_from_xml(xml_str: str) -> Dict[str, List[str]]:
    """Parse SAML 2.0 assertion and return a dict: { AttributeName -> [values...] }."""
    attrs: Dict[str, List[str]] = {}
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return attrs

    for attr in root.findall(".//saml2:Attribute", NS):
        name = attr.get("Name") or attr.get("FriendlyName", "unknown")
        values: List[str] = []
        for val_el in attr.findall(".//saml2:AttributeValue", NS):
            if val_el.text:
                v = val_el.text.strip()
                if v:
                    values.append(v)
        # dedupe while preserving order
        deduped: List[str] = []
        seen = set()
        for v in values:
            if v not in seen:
                deduped.append(v)
                seen.add(v)
        if deduped:
            attrs[name] = deduped
    return attrs

def _log_attr_map(attr_map: Dict[str, List[str]]) -> None:
    logger.info("=== SAML Attributes (normalized) ===")
    for k, v in attr_map.items():
        logger.info(" %s --> %s", k, v)

def _extract_FIRST_ATTRIB(attr_map: Dict[str, List[str]]) -> Optional[str]:
    vals = attr_map.get(FIRST_ATTRIB_NAME)
    return vals[0] if vals and vals[0] else None

def _extract_SECOND_ATTRIB(attr_map: Dict[str, List[str]]) -> Optional[str]:
    # Exact match only (not userId)
    vals = attr_map.get(SECOND_ATTRIB_NAME)
    return vals[0] if vals and vals[0] else None

# ========= NEW: Public key loader & encryption =========
def _load_public_key_from_secret():
    """
    Loads the public key from a PEM X.509 certificate stored in Secrets Manager.
    The secret may be either:
    - raw PEM string (-----BEGIN CERTIFICATE----- ...),
    - JSON with a key like 'publicCert'.
    Returns a cryptography public key object and caches it globally.
    """
    global _PUBLIC_KEY_OBJ
    if _PUBLIC_KEY_OBJ is not None:
        return _PUBLIC_KEY_OBJ

    # Fetch secret value
    try:
        resp = secrets_client.get_secret_value(SecretId=PUBLIC_KEY_SECRET_NAME)
    except botocore.exceptions.ClientError as e:
        logger.error("Failed to read secret %s: %s", PUBLIC_KEY_SECRET_NAME, e)
        raise

    secret_str = resp.get("SecretString")
    if not secret_str and "SecretBinary" in resp:
        secret_str = base64.b64decode(resp["SecretBinary"]).decode("utf-8", errors="ignore")

    if not secret_str:
        raise RuntimeError(f"Secret {PUBLIC_KEY_SECRET_NAME} was empty or missing content")

    pem = secret_str
    # Handle JSON-wrapped secret
    if secret_str.strip().startswith("{"):
        try:
            payload = json.loads(secret_str)
            # Heuristics: common field names
            for k in ("publicCert", "certificate", "cert", "PUBLIC_CERT", "x509"):
                if k in payload and isinstance(payload[k], str):
                    pem = payload[k]
                    break
        except Exception:
            pass

    if "-----BEGIN CERTIFICATE-----" not in pem:
        raise RuntimeError("Secret did not contain a PEM X.509 certificate (BEGIN CERTIFICATE)")

    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    _PUBLIC_KEY_OBJ = cert.public_key()
    logger.info("Public key successfully loaded from secret '%s'.", PUBLIC_KEY_SECRET_NAME)
    return _PUBLIC_KEY_OBJ

def _encrypt_with_public_key(value: str) -> str:
    """
    Encrypts UTF-8 value with the loaded public key using RSA-OAEP-SHA256.
    Returns Base64-encoded ciphertext (URL-safe not required here).
    """
    if value is None:
        return None
    pub = _load_public_key_from_secret()
    ciphertext = pub.encrypt(
        value.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")

# ========= Core handler =========
def handler(event, context):
    logger.info("=== Inbound Federation Trigger (summary) ===")
    logger.info(
        _pretty(
            {
                "userPoolId": event.get("userPoolId"),
                "userName": event.get("userName"),
                "triggerSource": event.get("triggerSource"),
                "region": event.get("region"),
                "debug": DEBUG,
                "stripPrefix": USERNAME_PREFIX_TO_STRIP or "(none)",
                "FIRST_ATTRIB_NAME": FIRST_ATTRIB_NAME,
                "SECOND_ATTRIB_NAME": SECOND_ATTRIB_NAME,
            }
        )
    )

    req = event.get("request", {}) or {}
    attrs_block = req.get("attributes", {}) or {}
    logger.info("=== request.attributes keys === %s", list(attrs_block.keys()))

    # Extract/normalize SAML attributes
    saml_obj = attrs_block.get("samlResponse")
    attr_map: Dict[str, List[str]] = {}

    # Case A: dict (flattened attributes and/or embedded encoded XML)
    if isinstance(saml_obj, dict):
        logger.info("=== samlResponse is dict; keys: %s ===", list(saml_obj.keys()))
        for k, v in saml_obj.items():
            if isinstance(v, str) and not LOG_SAML_XML and len(v) > LOG_PREVIEW_CHARS:
                logger.info(" %s --> %s", k, _safe_preview(v, LOG_PREVIEW_CHARS))
            else:
                logger.info(" %s --> %s", k, v)

        # capture direct FIRST/SECOND from flattened dict
        if FIRST_ATTRIB_NAME in saml_obj and saml_obj[FIRST_ATTRIB_NAME]:
            attr_map[FIRST_ATTRIB_NAME] = [str(saml_obj[FIRST_ATTRIB_NAME])]
        if SECOND_ATTRIB_NAME in saml_obj and saml_obj[SECOND_ATTRIB_NAME]:
            attr_map[SECOND_ATTRIB_NAME] = [str(saml_obj[SECOND_ATTRIB_NAME])]

        # parse embedded assertion if present
        for xml_key in ("SAMLResponse", "Assertion", "saml", "xml"):
            raw = saml_obj.get(xml_key)
            if isinstance(raw, str) and raw:
                xml = _maybe_decode_base64(raw) or raw
                if "<Assertion" in xml:
                    if LOG_SAML_XML:
                        logger.info(
                            "=== SAML XML (%s) ===\n%s",
                            xml_key,
                            _safe_preview(xml, LOG_PREVIEW_CHARS),
                        )
                    parsed = _parse_saml_attributes_from_xml(xml)
                    attr_map.update(parsed)

    # Case B: raw string (base64 or XML)
    elif isinstance(saml_obj, str) and saml_obj:
        xml = _maybe_decode_base64(saml_obj) or saml_obj
        if "<Assertion" in xml:
            if LOG_SAML_XML:
                logger.info("=== SAML XML (raw) ===\n%s", _safe_preview(xml, LOG_PREVIEW_CHARS))
            parsed = _parse_saml_attributes_from_xml(xml)
            attr_map.update(parsed)
        else:
            logger.info("=== samlResponse (string preview) === %s", _safe_preview(saml_obj, LOG_PREVIEW_CHARS))
    else:
        logger.info("samlResponse not present or unexpected type: %s", type(saml_obj).__name__)

    # Extract attributes
    if attr_map:
        _log_attr_map(attr_map)
    else:
        logger.warning("No SAML attributes could be normalized from inbound payload.")

    FIRST_ATTRIB = _extract_FIRST_ATTRIB(attr_map)
    SECOND_ATTRIB = _extract_SECOND_ATTRIB(attr_map)

    if FIRST_ATTRIB:
        logger.info("Extracted FIRST_ATTRIB (%s) = %s", FIRST_ATTRIB_NAME, FIRST_ATTRIB)
    else:
        logger.warning("FIRST_ATTRIB (%s) not found in SAML attributes.", FIRST_ATTRIB_NAME)

    if SECOND_ATTRIB:
        logger.info("Extracted SECOND_ATTRIB (%s) = %s", SECOND_ATTRIB_NAME, SECOND_ATTRIB)
    else:
        logger.info("SECOND_ATTRIB (%s) not found in SAML attributes.", SECOND_ATTRIB_NAME)
        # Fallback from env/default when SAML is empty/missing
        SECOND_ATTRIB = SECOND_ATTRIB_DEFAULT
        logger.info("Applied SECOND_ATTRIB fallback from env/default: %s", SECOND_ATTRIB)

    # --- Encrypt before persisting ---
    enc_first = _encrypt_with_public_key(FIRST_ATTRIB) if FIRST_ATTRIB else None
    enc_second = _encrypt_with_public_key(SECOND_ATTRIB) if SECOND_ATTRIB else None

    if DEBUG:
        # Debug log before and after (plaintext + Base64 ciphertext)
        if FIRST_ATTRIB:
            logger.info("[DEBUG] FIRST_ATTRIB plaintext: %s", FIRST_ATTRIB)
            logger.info("[DEBUG] FIRST_ATTRIB ciphertext (b64): %s", enc_first)
        if SECOND_ATTRIB:
            logger.info("[DEBUG] SECOND_ATTRIB plaintext: %s", SECOND_ATTRIB)
            logger.info("[DEBUG] SECOND_ATTRIB ciphertext (b64): %s", enc_second)

    # Single PutItem: store encrypted MRN & UID on the same record
    user_pool_id = event.get("userPoolId")
    user_name_raw = event.get("userName")

    if user_pool_id and user_name_raw and (enc_first or enc_second):
        # Normalize PK so reader/writer agree (strip prefix only if it matches)
        hash_value = _normalize_username(user_name_raw)
        ttl_value = int(time.time()) + TTL_SECONDS

        # Extra visibility to validate TTL correctness (epoch and human time)
        if DEBUG:
            logger.info(
                "TTL CHECK: now=%s (%s), TTL_SECONDS=%s, computed_ttl=%s (%s)",
                int(time.time()), time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()),
                TTL_SECONDS, ttl_value, time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ttl_value))
            )

        # ALWAYS write to 'MRN' and 'UID' (schema fixed), but encrypted values
        item = {HASH_NAME: hash_value, TTL_ATTR_NAME: ttl_value}  # <-- use env-driven TTL name
        if enc_first:
            item["MRN"] = enc_first
        if enc_second:
            item["UID"] = enc_second

        if DEBUG:
            logger.info("DEBUG: PK(raw)=%s, PK(normalized)=%s", user_name_raw, hash_value)
            logger.info("DEBUG: DynamoDB PutItem payload:\n%s", _pretty(item))

        try:
            table.put_item(Item=item)
            logger.info(
                "PutItem ok: %s { %s=%s } ttl=%s",
                DDB_TABLE,
                HASH_NAME,
                hash_value,
                ttl_value,
            )
        except botocore.exceptions.ClientError as e:
            logger.error("PutItem failed: %s", e)
            raise
    elif not (user_pool_id and user_name_raw):
        logger.warning("Missing userPoolId/userName in event; skipping DynamoDB write.")
    else:
        logger.warning("Neither encrypted MRN nor encrypted UID present; nothing to write.")

    return event


# === Single AWS Lambda entry point ===
def lambda_handler(event, context):
    return handler(event, context)
