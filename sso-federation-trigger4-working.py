# filename: lambda_function.py
# runtime: Python 3.10

import os
import time
import json
import base64
import logging
from typing import Dict, List, Any, Optional
import boto3
import botocore
import xml.etree.ElementTree as ET


def lambda_handler(event, context):
    return handler(event, context)


# ========= Configuration (env) =========
DDB_TABLE = os.environ.get("DDB_TABLE")  # required
TTL_SECONDS = int(os.environ.get("TTL_SECONDS", "120"))
LOG_SAML_XML = os.environ.get("LOG_SAML_XML", "false").lower() == "true"
LOG_PREVIEW_CHARS = int(os.environ.get("LOG_PREVIEW_CHARS", "800"))
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
USERNAME_PREFIX_TO_STRIP = os.environ.get("USERNAME_PREFIX_TO_STRIP", "")  # e.g., "O365-SSO_"

# Configurable SAML attribute names (defaults chosen to match existing, working behavior)
FIRST_ATTRIB_NAME = os.environ.get("FIRST_ATTRIB", "MRN")
SECOND_ATTRIB_NAME = os.environ.get("SECOND_ATTRIB", "UID")

if not DDB_TABLE:
    raise RuntimeError("Environment variable DDB_TABLE is required")

# ========= AWS clients/resources =========
ddb_resource = boto3.resource("dynamodb")
table = ddb_resource.Table(DDB_TABLE)

# ========= Logging =========
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ========= Constants =========
NS = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
HASH_NAME = "user_name"  # DynamoDB partition key attribute name


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

    # Single PutItem: store to fixed DynamoDB schema keys MRN/UID
    user_pool_id = event.get("userPoolId")
    user_name_raw = event.get("userName")

    if user_pool_id and user_name_raw and (FIRST_ATTRIB or SECOND_ATTRIB):
        # Normalize PK so reader/writer agree (strip prefix only if it matches)
        hash_value = _normalize_username(user_name_raw)
        ttl_value = int(time.time()) + TTL_SECONDS

        # ALWAYS write to 'MRN' and 'UID' to preserve schema used by existing consumers
        item = {HASH_NAME: hash_value, "ttl": ttl_value}
        if FIRST_ATTRIB:
            item["MRN"] = FIRST_ATTRIB
        if SECOND_ATTRIB:
            item["UID"] = SECOND_ATTRIB

        if DEBUG:
            logger.info("DEBUG: PK(raw)=%s, PK(normalized)=%s", user_name_raw, hash_value)
            logger.info("DEBUG: DynamoDB PutItem payload:\n%s", _pretty(item))

        try:
            table.put_item(Item=item)
            logger.info("PutItem ok: %s { %s=%s } ttl=%s", DDB_TABLE, HASH_NAME, hash_value, ttl_value)
        except botocore.exceptions.ClientError as e:
            logger.error("PutItem failed: %s", e)
            raise
    elif not (user_pool_id and user_name_raw):
        logger.warning("Missing userPoolId/userName in event; skipping DynamoDB write.")
    else:
        logger.warning("Neither MRN nor UID present; nothing to write.")

    return event


# AWS Lambda entry point for Handler: lambda_function.lambda_handler
def lambda_handler(event, context):
    return handler(event, context)