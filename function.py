import os
import json
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
import boto3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

# ===== AWS clients/resources =====
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ.get("DDB_TABLE_NAME", "amr_robot_state"))

# ===== Endpoints =====
AUTH0_TOKEN_URL = "https://fetchcore.auth0.com/oauth/token"

ROBOTS_URL = "https://iveco.robots.zebrasymmetry.com/api/v1/robots/?page=1&page_size=1000"
EVENTS_INCOMPLETE_URL = "https://iveco.robots.zebrasymmetry.com/api/v1/executionstate?state=Incomplete"

# Clear error trigger
CLEAR_ERROR_URL = "https://iveco.robots.zebrasymmetry.com/api/v1/trigger/builtin/clear_error"

# Trigger ricarica (activate) per specifici robot
CHARGE_TRIGGER_URL_BY_ROBOT_NAME: Dict[str, str] = {
    "freight100-2424": "https://iveco.robots.zebrasymmetry.com/api/v1/trigger/9ed4cf80-2a7c-406e-a207-2d27a7f37a07/activate",
    "freight100-2439": "https://iveco.robots.zebrasymmetry.com/api/v1/trigger/61994945-8d50-4e42-9eb2-dfb20a50636f/activate",
    "freight100-2177": "https://iveco.robots.zebrasymmetry.com/api/v1/trigger/a740ba57-bc6b-46d8-96dc-7e7c8338376f/activate",
}

# ===== Constants =====
ROBOT_ERROR_KEY_PREFIX = "robot:"                 # key stato sintetico "robot:<id>"
INCOMPLETE_EVENTS_KEY = "__incomplete_events__"   # key fissa anti-spam eventi
CLEAR_ATTEMPTS_KEY_PREFIX = "clear_attempts:"     # key contatore clear "clear_attempts:<id>"
MAX_CLEAR_ATTEMPTS = 5


# -------------------------
# Env helpers
# -------------------------
def env_true(name: str, default: str = "false") -> bool:
    v = (os.environ.get(name, default) or "").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


# -------------------------
# HTTP helpers
# -------------------------
def _http_post_form(
    url: str,
    form: Dict[str, str],
    headers: Dict[str, str] | None = None,
    timeout: int = 20
) -> Dict[str, Any]:
    body = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get_json(
    url: str,
    headers: Dict[str, str] | None = None,
    timeout: int = 20
) -> Dict[str, Any]:
    req = urllib.request.Request(url, method="GET")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str] | None = None,
    timeout: int = 20
) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if raw.strip():
                return json.loads(raw)
            return {"ok": True}
    except HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8")
        except Exception:
            pass
        raise RuntimeError(f"HTTPError {e.code} calling {url}: {err_body or str(e)}") from e
    except URLError as e:
        raise RuntimeError(f"URLError calling {url}: {str(e)}") from e


def _http_post_empty(
    url: str,
    headers: Dict[str, str] | None = None,
    timeout: int = 20
) -> Dict[str, Any]:
    """
    POST senza body (come curl --request POST ... senza --data).
    """
    req = urllib.request.Request(url, data=b"", method="POST")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if raw.strip():
                try:
                    return json.loads(raw)
                except Exception:
                    return {"ok": True, "raw": raw}
            return {"ok": True}
    except HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8")
        except Exception:
            pass
        raise RuntimeError(f"HTTPError {e.code} calling {url}: {err_body or str(e)}") from e
    except URLError as e:
        raise RuntimeError(f"URLError calling {url}: {str(e)}") from e


# -------------------------
# Auth / API calls
# -------------------------
def get_access_token() -> str:
    username = os.environ["AUTH0_USERNAME"]
    password = os.environ["AUTH0_PASSWORD"]
    client_id = os.environ["AUTH0_CLIENT_ID"]
    client_secret = os.environ["AUTH0_CLIENT_SECRET"]

    form = {
        "username": username,
        "password": password,
        "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
        "realm": "Username-Password-Authentication",
        "audience": "fetchcore",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "profile email fetchcore:all_access openid",
    }

    token_resp = _http_post_form(AUTH0_TOKEN_URL, form=form)
    token = token_resp.get("access_token")
    if not token:
        raise RuntimeError(f"Auth0 token response missing access_token: {token_resp}")
    return token


def fetch_robots(token: str) -> List[Dict[str, Any]]:
    data = _http_get_json(ROBOTS_URL, headers={"Authorization": f"Bearer {token}"})
    robots = data.get("results")
    if robots is None:
        if isinstance(data, list):
            robots = data
        else:
            raise RuntimeError(f"Unexpected robots response shape: {data.keys()}")
    return robots


def fetch_incomplete_events(token: str) -> List[Dict[str, Any]]:
    data = _http_get_json(EVENTS_INCOMPLETE_URL, headers={"Authorization": f"Bearer {token}"})
    results = data.get("results")
    if results is None:
        if isinstance(data, list):
            results = data
        else:
            raise RuntimeError(f"Unexpected events response shape: {data.keys()}")
    return results


def trigger_clear_error(token: str, robot_name: str) -> Dict[str, Any]:
    payload = {"robot_name": robot_name, "payload_footprint": None}
    return _http_post_json(
        CLEAR_ERROR_URL,
        payload=payload,
        headers={"Authorization": f"Bearer {token}"}
    )


def trigger_charge_activate(token: str, robot_name: str) -> Dict[str, Any]:
    url = CHARGE_TRIGGER_URL_BY_ROBOT_NAME.get(robot_name)
    if not url:
        raise RuntimeError(f"Nessun trigger di ricarica configurato per robot_name={robot_name}")
    return _http_post_empty(
        url,
        headers={"Authorization": f"Bearer {token}"}
    )


# -------------------------
# Parsing / classification
# -------------------------
def parse_utc_z(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def is_robot_in_error(rb: Dict[str, Any]) -> Tuple[bool, str]:
    status = (rb.get("status") or "").upper()
    current_mode = (rb.get("current_mode") or "").upper()

    error_status = rb.get("error_status")
    error_sources = rb.get("error_sources")
    safety_violation = bool(rb.get("safety_field_violation", False))

    bad_statuses = {"OFFLINE"}  # OFFLINE considerato errore
    mode_is_error = ("ERROR" in current_mode)

    in_error = (
        (status in bad_statuses)
        or mode_is_error
        or (error_status is not None)
        or (error_sources is not None)
        or safety_violation
    )

    reason_parts = []
    if status in bad_statuses:
        reason_parts.append(f"status={status}")
    if mode_is_error:
        reason_parts.append(f"current_mode={current_mode}")
    if error_status is not None:
        if isinstance(error_status, dict) and "type" in error_status:
            reason_parts.append(f"error_status.type={error_status.get('type')}")
        else:
            reason_parts.append("error_status!=null")
    if error_sources is not None:
        reason_parts.append("error_sources!=null")
    if safety_violation:
        reason_parts.append("safety_field_violation=true")

    reason = ", ".join(reason_parts) if reason_parts else ""
    return in_error, reason


def can_auto_clear(rb: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Clear error SOLO SE:
      payload_footprint == NO_PAYLOAD
      current_mode == MODE_ERROR
      status == IDLE
      localized == True
    """
    payload_fp = (rb.get("payload_footprint") or "").upper()
    mode = (rb.get("current_mode") or "").upper()
    status = (rb.get("status") or "").upper()
    localized = bool(rb.get("localized", False))

    ok = (payload_fp == "NO_PAYLOAD") and (mode == "MODE_ERROR") and (status == "IDLE") and localized
    why = f"payload_footprint={payload_fp}, current_mode={mode}, status={status}, localized={localized}"
    return ok, why


def is_offline(rb: Dict[str, Any]) -> bool:
    return (rb.get("status") or "").upper() == "OFFLINE"


# -------------------------
# DynamoDB helpers
# -------------------------
def ddb_get_item(key: str) -> Dict[str, Any]:
    resp = table.get_item(Key={"robot_id": key})
    return (resp.get("Item", {}) or {})


def ddb_get_status(key: str) -> str:
    item = ddb_get_item(key)
    return item.get("status") or ""


def ddb_put_item(item: Dict[str, Any]) -> None:
    table.put_item(Item=item)


def ddb_put_status(key: str, status: str, extra: Dict[str, Any] | None = None) -> None:
    item = {
        "robot_id": key,
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        item.update(extra)
    ddb_put_item(item)


def ddb_get_int(key: str, field: str, default: int = 0) -> int:
    item = ddb_get_item(key)
    val = item.get(field)
    try:
        return int(val)
    except Exception:
        return default


def ddb_set_clear_attempts(robot_id: str, attempts: int) -> None:
    key = f"{CLEAR_ATTEMPTS_KEY_PREFIX}{robot_id}"
    ddb_put_item({
        "robot_id": key,
        "attempts": int(attempts),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def ddb_get_clear_attempts(robot_id: str) -> int:
    key = f"{CLEAR_ATTEMPTS_KEY_PREFIX}{robot_id}"
    return ddb_get_int(key, "attempts", 0)


# -------------------------
# SNS
# -------------------------
def notify_sns(topic_arn: str, subject: str, message: str) -> None:
    sns.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=message,
    )


# -------------------------
# Lambda entrypoint
# -------------------------
def lambda_handler(event, context):
    # Topic standard (già esistente)
    topic_arn = os.environ.get("SNS_TOPIC_ARN")

    # Topic dedicato OFFLINE (con le 3 email K+N come subscription)
    offline_topic_arn = os.environ.get("OFFLINE_SNS_TOPIC_ARN")

    auto_clear = env_true("AUTO_CLEAR_ERROR", "false")
    auto_send_charge = env_true("AUTO_SEND_CHARGE", "false")

    print(f"SNS_TOPIC_ARN = {topic_arn}")
    print(f"OFFLINE_SNS_TOPIC_ARN = {offline_topic_arn}")
    print(f"AUTO_CLEAR_ERROR env = {auto_clear}")
    print(f"AUTO_SEND_CHARGE env = {auto_send_charge}")
    print(f"MAX_CLEAR_ATTEMPTS = {MAX_CLEAR_ATTEMPTS}")

    token = get_access_token()

    # =========================
    # 1) ROBOTS
    # =========================
    robots = fetch_robots(token)

    print("=== STATO ROBOT RICEVUTI ===")
    for rb in robots:
        print(
            f"- {rb.get('display_name') or rb.get('name')} | "
            f"name={rb.get('name')} | "
            f"status={rb.get('status')} | current_mode={rb.get('current_mode')} | "
            f"payload_footprint={rb.get('payload_footprint')} | localized={rb.get('localized')} | "
            f"safety_field_violation={rb.get('safety_field_violation')} | "
            f"error_status={rb.get('error_status')} | error_sources={rb.get('error_sources')}"
        )
    print("=== FINE LISTA ROBOT ===")

    # Alert standard (mail già esistente) + alert offline (solo topic K+N)
    robot_alerts: List[str] = []
    offline_alerts: List[str] = []

    robots_in_error_now: List[Dict[str, Any]] = []
    charge_triggered: List[Dict[str, Any]] = []

    for rb in robots:
        robot_id = str(rb.get("id"))
        ddb_key = f"{ROBOT_ERROR_KEY_PREFIX}{robot_id}"

        robot_name = rb.get("name") or ""
        display_name = rb.get("display_name") or robot_name or f"robot-{robot_id}"

        # stato attuale
        in_error_now, reason = is_robot_in_error(rb)
        curr_state = "ERROR" if in_error_now else "OK"
        offline_now = is_offline(rb)

        # stato precedente da DDB (per capire recovery OFFLINE)
        prev_item = ddb_get_item(ddb_key)
        prev_state = (prev_item.get("status") or "").upper()      # "OK" / "ERROR" / ""
        prev_raw_status = (prev_item.get("raw_status") or "").upper()

        # Email: solo su cambio stato (o prima run se già ERROR)
        if prev_state != curr_state:
            if curr_state == "ERROR":
                if prev_state:
                    msg = f"❌ {display_name} è entrato in ERRORE ({reason})"
                else:
                    msg = f"❌ {display_name} è attualmente in ERRORE ({reason})"

                robot_alerts.append(msg)

                # EXTRA recipients solo se OFFLINE
                if offline_now:
                    offline_alerts.append(msg)

            else:
                if prev_state:
                    msg = f"✅ {display_name} è tornato OK"
                    robot_alerts.append(msg)

                    # se prima era OFFLINE, notifichiamo anche al topic offline (ritorno online)
                    if prev_raw_status == "OFFLINE":
                        offline_alerts.append(msg)

        if in_error_now:
            robots_in_error_now.append({
                "id": rb.get("id"),
                "name": rb.get("name"),
                "display_name": rb.get("display_name"),
                "status": rb.get("status"),
                "current_mode": rb.get("current_mode"),
                "payload_footprint": rb.get("payload_footprint"),
                "localized": rb.get("localized"),
                "reason": reason,
                "ip": rb.get("ip"),
                "last_status_change": rb.get("last_status_change"),
            })
            print(f"!!! ERRORE su {display_name}: {reason}")

        # Se il robot è OK: azzera contatore tentativi clear
        if not in_error_now:
            attempts = ddb_get_clear_attempts(robot_id)
            if attempts != 0:
                print(f"Reset clear attempts per {display_name} (robot_id={robot_id}) da {attempts} a 0 (robot OK).")
                ddb_set_clear_attempts(robot_id, 0)

        # Auto clear: riprova ad ogni esecuzione finché in errore, ma max 5 tentativi totali
        if auto_clear and in_error_now:
            ok_clear, why = can_auto_clear(rb)
            attempts = ddb_get_clear_attempts(robot_id)

            if attempts >= MAX_CLEAR_ATTEMPTS:
                print(f"--> AUTO_CLEAR_ERROR: STOP per {display_name}. Tentativi raggiunti: {attempts}/{MAX_CLEAR_ATTEMPTS}.")
            elif not ok_clear:
                print(f"--> AUTO_CLEAR_ERROR: NON invio clear_error per {display_name}. Condizioni non soddisfatte: {why}")
            else:
                if not robot_name:
                    msg = f"⚠️ AUTO_CLEAR_ERROR attivo, ma robot_name mancante per {display_name} (id={robot_id})"
                    print(msg)
                    # (Queste notifiche restano solo sul topic standard: NON vanno a K+N)
                    if prev_state != curr_state:
                        robot_alerts.append(msg)
                else:
                    new_attempts = attempts + 1
                    ddb_set_clear_attempts(robot_id, new_attempts)

                    try:
                        print(
                            f"--> AUTO_CLEAR_ERROR: invio clear_error per {display_name} "
                            f"(robot_name={robot_name}). Condizioni OK: {why}. Tentativo {new_attempts}/{MAX_CLEAR_ATTEMPTS}"
                        )
                        clear_resp = trigger_clear_error(token=token, robot_name=robot_name)
                        print(f"<-- clear_error OK per {robot_name}: {clear_resp}")

                        # SOLO al PRIMO tentativo: manda in ricarica (se abilitato e configurato)
                        if auto_send_charge and new_attempts == 1:
                            if robot_name in CHARGE_TRIGGER_URL_BY_ROBOT_NAME:
                                try:
                                    print(f"--> CHARGE: invio trigger ricarica per {robot_name} (solo al tentativo #1).")
                                    ch_resp = trigger_charge_activate(token=token, robot_name=robot_name)
                                    print(f"<-- CHARGE OK per {robot_name}: {ch_resp}")
                                    charge_triggered.append({"robot_name": robot_name, "response": ch_resp})

                                    # solo topic standard
                                    if prev_state != curr_state:
                                        robot_alerts.append(f"🔌 Inviato comando RICARICA per {display_name} (solo tentativo #1)")
                                except Exception as ce:
                                    print(f"<-- CHARGE FALLITO per {robot_name}: {ce}")
                                    if prev_state != curr_state:
                                        robot_alerts.append(f"⚠️ Comando RICARICA FALLITO per {display_name}: {ce}")
                            else:
                                print(f"--> CHARGE: nessun trigger configurato per robot_name={robot_name}. Non invio ricarica.")
                        else:
                            if new_attempts == 1 and not auto_send_charge:
                                print("--> CHARGE: AUTO_SEND_CHARGE è disattivato, non invio ricarica.")
                            elif new_attempts != 1:
                                print(f"--> CHARGE: tentativo clear #{new_attempts}, non reinvio ricarica (solo #1).")

                        # solo topic standard
                        if prev_state != curr_state:
                            robot_alerts.append(
                                f"🧹 Clear error inviato per {display_name} (robot_name={robot_name}) "
                                f"[tentativo {new_attempts}/{MAX_CLEAR_ATTEMPTS}]"
                            )

                    except Exception as e:
                        print(f"<-- clear_error FALLITO per {robot_name}: {e}")
                        if prev_state != curr_state:
                            robot_alerts.append(
                                f"⚠️ Clear error FALLITO per {display_name} (robot_name={robot_name}): {e} "
                                f"[tentativo {new_attempts}/{MAX_CLEAR_ATTEMPTS}]"
                            )

        # Salva stato sintetico
        ddb_put_status(
            key=ddb_key,
            status=curr_state,
            extra={
                "raw_status": rb.get("status") or "",
                "raw_mode": rb.get("current_mode") or "",
                "raw_payload_footprint": rb.get("payload_footprint") if rb.get("payload_footprint") is not None else "",
                "raw_localized": bool(rb.get("localized", False)),
            }
        )

    # ===== Publish SNS: standard =====
    if robot_alerts and topic_arn:
        notify_sns(
            topic_arn=topic_arn,
            subject="AMR – Stato/variazioni robot",
            message="\n".join(robot_alerts)
        )
        print("Notifica robot (standard) inviata via SNS.")
    else:
        print("Nessuna notifica robot standard (o SNS_TOPIC_ARN non impostato).")

    # ===== Publish SNS: OFFLINE-only =====
    if offline_alerts and offline_topic_arn:
        notify_sns(
            topic_arn=offline_topic_arn,
            subject="AMR – OFFLINE",
            message="\n".join(offline_alerts)
        )
        print("Notifica robot OFFLINE inviata via SNS (topic dedicato).")
    else:
        print("Nessuna notifica OFFLINE (o OFFLINE_SNS_TOPIC_ARN non impostato, o nessun offline).")

    # =========================
    # 2) EVENTI: Incomplete > 30 minuti + anti-spam su lista
    # =========================
    now_utc = datetime.now(timezone.utc)
    threshold = now_utc - timedelta(minutes=30)

    events = fetch_incomplete_events(token)
    old_incomplete: List[Dict[str, Any]] = []

    print(f"=== EVENTI INCOMPLETE (tot={len(events)}) ===")
    for ev in events:
        st = ev.get("start_time")
        if not st:
            continue

        start_dt = parse_utc_z(st)
        if start_dt < threshold:
            old_incomplete.append({
                "execution_id": ev.get("execution_id"),
                "robot": ev.get("robot"),
                "event_type": ev.get("event_type"),
                "current_action": ev.get("current_action"),
                "start_time": ev.get("start_time"),
                "age_minutes": int((now_utc - start_dt).total_seconds() // 60),
            })

    signature = "|".join(sorted([e.get("execution_id") or "" for e in old_incomplete]))
    prev_signature = ddb_get_status(INCOMPLETE_EVENTS_KEY)

    if old_incomplete:
        print("Eventi INCOMPLETE > 30 min trovati:", old_incomplete)
        if signature != prev_signature:
            lines = ["⚠️ Eventi INCOMPLETE più vecchi di 30 minuti:"]
            for e in old_incomplete:
                lines.append(
                    f"- robot={e['robot']} type={e['event_type']} action={e['current_action']} "
                    f"age={e['age_minutes']}m start={e['start_time']} exec_id={e['execution_id']}"
                )

            if topic_arn:
                notify_sns(
                    topic_arn=topic_arn,
                    subject=f"AMR – Incomplete > 30 min ({len(old_incomplete)})",
                    message="\n".join(lines)
                )
                print("Notifica eventi inviata via SNS.")
            else:
                print("SNS_TOPIC_ARN non impostato: niente email eventi.")

            ddb_put_status(INCOMPLETE_EVENTS_KEY, signature)
        else:
            print("Eventi vecchi presenti ma nessun cambiamento: non rinotifico (anti-spam).")
    else:
        print("Nessun evento INCOMPLETE più vecchio di 30 minuti.")
        if prev_signature:
            ddb_put_status(INCOMPLETE_EVENTS_KEY, "")

    return {
        "ok": (len(robots_in_error_now) == 0 and len(old_incomplete) == 0),
        "auto_clear_enabled": auto_clear,
        "auto_send_charge_enabled": auto_send_charge,
        "robot_alerts_sent": robot_alerts,
        "offline_alerts_sent": offline_alerts,
        "robots_in_error_now": robots_in_error_now,
        "charge_triggered": charge_triggered,
        "robots_count": len(robots),
        "old_incomplete_events": old_incomplete,
        "incomplete_total": len(events),
    }
