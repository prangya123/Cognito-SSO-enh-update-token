# filename: pre_token_generation.py
# runtime: Python 3.10

import os
import json
import logging
from typing import Any, Dict, Optional
import boto3
import botocore

# ========= Configuration (env) =========
DDB_TABLE = os.environ.get("DDB_TABLE")  # required
HASH_NAME = os.environ.get("HASH_NAME", "user_name")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
USERNAME_PREFIX_TO_STRIP = os.environ.get("USERNAME_PREFIX_TO_STRIP", "")

# NEW: dynamic DynamoDB attribute names (default to MRN/UID)
FIRST_ATTRIB_NAME = os.environ.get("FIRST_ATTRIB", "MRN")
SECOND_ATTRIB_NAME = os.environ.get("SECOND_ATTRIB", "UID")

if not DDB_TABLE:
    raise RuntimeError("Environment variable DDB_TABLE is required")

# ========= AWS resources =========
ddb = boto3.resource("dynamodb")
table = ddb.Table(DDB_TABLE)

# ========= Logging =========
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _pretty(o: Any) -> str:
    return json.dumps(o, indent=2, default=str)


def _normalize_username(raw: str) -> str:
    prefix = USERNAME_PREFIX_TO_STRIP
    if prefix and isinstance(raw, str) and raw.startswith(prefix):
        return raw[len(prefix):]
    return raw


def _get_username_from_event(event: Dict[str, Any]) -> Optional[str]:
    return event.get("userName")


def _read_user_attrs_from_ddb(user_name_raw: str) -> Dict[str, Optional[str]]:
    """
    Reads FIRST_ATTRIB_NAME and SECOND_ATTRIB_NAME dynamically from DynamoDB.
    Example:
       FIRST_ATTRIB_NAME="MRN", SECOND_ATTRIB_NAME="UID"
       Returns: {"MRN": "...", "UID": "..."}
    """
    pk = _normalize_username(user_name_raw)

    try:
        resp = table.get_item(
            Key={HASH_NAME: pk},
            ConsistentRead=True
        )
    except botocore.exceptions.ClientError as e:
        logger.error("DynamoDB GetItem failed: %s", e)
        return {FIRST_ATTRIB_NAME: None, SECOND_ATTRIB_NAME: None}

    item = resp.get("Item") or {}

    first_val = item.get(FIRST_ATTRIB_NAME)
    second_val = item.get(SECOND_ATTRIB_NAME)

    if DEBUG:
        logger.info("DEBUG: DDB read: %s=%s → %s=%s, %s=%s",
                    HASH_NAME, pk,
                    FIRST_ATTRIB_NAME, first_val,
                    SECOND_ATTRIB_NAME, second_val)

    return {FIRST_ATTRIB_NAME: first_val, SECOND_ATTRIB_NAME: second_val}


def handler(event, context):
    logger.info("=== Pre Token Generation (summary) ===")
    logger.info(_pretty({
        "triggerSource": event.get("triggerSource"),
        "userPoolId": event.get("userPoolId"),
        "userName": event.get("userName"),
        "region": event.get("region"),
        "debug": DEBUG,
        "FIRST_ATTRIB_NAME": FIRST_ATTRIB_NAME,
        "SECOND_ATTRIB_NAME": SECOND_ATTRIB_NAME,
    }))

    user_name_raw = _get_username_from_event(event)
    if not user_name_raw:
        logger.warning("userName missing; returning event unchanged.")
        return event

    # Read dynamic attributes from DynamoDB
    attrs = _read_user_attrs_from_ddb(user_name_raw)
    FIRST_VAL = attrs.get(FIRST_ATTRIB_NAME)
    SECOND_VAL = attrs.get(SECOND_ATTRIB_NAME)

    # Ensure response dict
    response = event.get("response")
    if not isinstance(response, dict):
        response = {}
        event["response"] = response

    # Ensure V3 structure
    cas = response.get("claimsAndScopeOverrideDetails")
    if not isinstance(cas, dict):
        cas = {}
        response["claimsAndScopeOverrideDetails"] = cas

    idgen = cas.get("idTokenGeneration")
    if not isinstance(idgen, dict):
        idgen = {}
        cas["idTokenGeneration"] = idgen

    accgen = cas.get("accessTokenGeneration")
    if not isinstance(accgen, dict):
        accgen = {}
        cas["accessTokenGeneration"] = accgen

    add_id = idgen.get("claimsToAddOrOverride")
    if not isinstance(add_id, dict):
        add_id = {}
        idgen["claimsToAddOrOverride"] = add_id

    add_acc = accgen.get("claimsToAddOrOverride")
    if not isinstance(add_acc, dict):
        add_acc = {}
        accgen["claimsToAddOrOverride"] = add_acc

    # ---- Add dynamic claims ----
    if FIRST_VAL:
        add_id[FIRST_ATTRIB_NAME] = str(FIRST_VAL)
        add_acc[FIRST_ATTRIB_NAME] = str(FIRST_VAL)
        logger.info("Added claim '%s' = %s", FIRST_ATTRIB_NAME, FIRST_VAL)
    else:
        logger.info("%s not found in DynamoDB.", FIRST_ATTRIB_NAME)

    if SECOND_VAL:
        add_id[SECOND_ATTRIB_NAME] = str(SECOND_VAL)
        add_acc[SECOND_ATTRIB_NAME] = str(SECOND_VAL)
        logger.info("Added claim '%s' = %s", SECOND_ATTRIB_NAME, SECOND_VAL)
    else:
        logger.info("%s not found in DynamoDB.", SECOND_ATTRIB_NAME)

    if DEBUG:
        logger.info("=== Token overrides (V3) === %s", _pretty({
            "idTokenGeneration": {"claimsToAddOrOverride": add_id},
            "accessTokenGeneration": {"claimsToAddOrOverride": add_acc},
        }))

    return event


def lambda_handler(event, context):
    print("==========")
    print(event)
    return handler(event, context)