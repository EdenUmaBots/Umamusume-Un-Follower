"""
unfollower_bot.py -- Icarus Un-follower for Umamusume (headless).

Talks DIRECTLY to the live Cygames game server (same protocol the Icarus career
bot uses), so the game only needs to be open once -- to capture your account
auth. After that everything is headless:

  auth capture (auth_capture.py, game running)  ->  account.json
  login + friend/index (uma_client.py)          ->  your follower list
  classify inactive (this file)                 ->  who to remove
  friend/un_follower (uma_client.py)            ->  removed, paced by delays

No Frida injection of the game's own functions, no in-game action needed to
remove -- the server does the removal exactly as if you'd tapped "Remove
Follower". Frida is used ONLY for the one-time auth grab (auth_capture.py).

--------------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------------
Run with NO arguments (or "Start Icarus Unfollower.vbs" / the exe) to open the
dashboard UI: pick an inactivity period + human-like delays, then Scan / Remove
with a live log. Or from the command line:

  python unfollower_bot.py analyze --days 30
      Login + friend/index, report who's been inactive >= N days. Removes
      NOTHING. (First run captures auth off the game; after that it's headless.)

  python unfollower_bot.py run --days 30 --max 0 --arm --yes
      Remove inactive followers via friend/un_follower. DRY unless --arm --yes.
      --max 0 = remove everyone inactive; a number caps it.

--------------------------------------------------------------------------------
PRIVACY
--------------------------------------------------------------------------------
follower_data/account.json holds your REAL auth (viewer_id, auth_key, steam
ticket) and follower_data/followers.json holds real viewer ids. Both are
git-ignored and stay on your machine -- never share them.
"""

import argparse
import glob
import json
import os
import queue
import random
import re
import sys
import threading
import time
import webbrowser
import tkinter as tk
from tkinter import messagebox

import frida

import auth_capture
import uma_client

PROCESS_NAME = "UmamusumePrettyDerby.exe"  # only for the one-time auth capture
APP_NAME = "Icarus Un-follower"
APP_SHORT = "Un-follower"
DISCORD_URL = "https://discord.gg/wpbd3hTBDc"
DISCORD_BLURPLE = "#5865F2"
# When bundled into a single exe, __file__ lives in a temp dir, so anchor
# follower_data/ next to the real executable instead.
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)          # PyInstaller
elif "__compiled__" in globals():
    _d = os.environ.get("NUITKA_ONEFILE_DIRECTORY")     # Nuitka onefile
    BASE_DIR = _d if _d else os.path.dirname(os.path.abspath(sys.argv[0]))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "follower_data")

# Field-name heuristics for auto-detecting the follower-list schema. Umamusume
# tends to use viewer_id + a *_time unix stamp; we detect rather than hard-code
# so a game patch that renames a field doesn't silently break us.
ID_KEYS = ("viewer_id", "user_id", "friend_viewer_id", "target_viewer_id", "member_id", "id")
NAME_KEYS = ("trainer_name", "name", "user_name", "nickname")
TIME_KEY_RE = re.compile(r"(last.*(login|access|active|play).*time)|((login|access|active|play).*time)|last_.*_time", re.I)
# Relationship flags (confirmed live on Gallop.UserFriend: IsFollower/IsFollow/
# IsFriend). Wire form is snake_case ints/bools. Used so we can remove *only*
# non-mutual inactive followers by default and never cut a mutual friend.
REL_FOLLOWER_KEYS = ("is_follower", "follower", "is_followed_by")
REL_FOLLOW_KEYS = ("is_follow", "follow", "following", "is_following")
REL_FRIEND_KEYS = ("is_friend", "friend", "is_mutual", "mutual")
# a plausible unix seconds timestamp: 2017-01-01 .. 2035-01-01
TS_MIN, TS_MAX = 1_483_228_800, 2_051_222_400

# Inactivity periods offered in the UI dropdown, from aggressive to conservative.
# A follower counts as "inactive" when their last login is older than this.
PERIOD_OPTIONS = ["12 hours", "1 day", "2 days", "3 days",
                  "7 days", "14 days", "21 days", "1 month"]
# Conservative default (== the old 30-day behaviour): only long-idle followers.
PERIOD_DEFAULT = "1 month"


def period_to_seconds(label):
    """Convert a period label ('12 hours', '3 days', '1 month', ...) to seconds.
    Understands hours / days / weeks / months; falls back to days, then 30 days."""
    parts = str(label).split()
    try:
        n = float(parts[0])
    except (ValueError, IndexError):
        return 30 * 86400.0
    unit = parts[1].lower() if len(parts) > 1 else "days"
    if unit.startswith("hour"):
        return n * 3600.0
    if unit.startswith("week"):
        return n * 7 * 86400.0
    if unit.startswith("month"):
        return n * 30 * 86400.0
    return n * 86400.0  # days (default)


def days_to_label(days):
    """Render a numeric --days value as a friendly period label for reports."""
    days = float(days)
    if days < 1:
        h = days * 24
        return f"{h:g} hour" + ("s" if h != 1 else "")
    if days >= 30 and days % 30 == 0:
        months = int(days // 30)
        return f"{months} month" + ("s" if months != 1 else "")
    return f"{days:g} day" + ("s" if days != 1 else "")


# --------------------------------------------------------------------------- #
# Follower-list schema auto-detection                                          #
# --------------------------------------------------------------------------- #
_DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")


def _to_unix(v):
    """Normalise a last-login value to a unix timestamp (float), or None.
    Umamusume sends last_login_time as a 'YYYY-MM-DD HH:MM:SS' string in the
    player's LOCAL time (confirmed against the in-game 'Xh ago' labels); some
    fields are plain unix ints. '0000-00-00 ...' / '' mean 'never'."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v) if TS_MIN <= v <= TS_MAX else None
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("0000") or not _DT_RE.match(s):
            return None
        try:
            return time.mktime(time.strptime(s[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            return None
    return None


def _looks_like_ts(v):
    return _to_unix(v) is not None


def _entry_fields(entry):
    """Given a candidate list entry (dict), find its (id, name, time) fields.
    Looks one level into nested user objects too (e.g. {"user_info": {...}})."""
    if not isinstance(entry, dict):
        return None
    scopes = [entry]
    for v in entry.values():
        if isinstance(v, dict):
            scopes.append(v)

    id_field = name_field = time_field = None
    id_scope = None
    for scope in scopes:
        for k in ID_KEYS:
            if k in scope and isinstance(scope[k], int) and scope[k] > 0:
                id_field, id_scope = k, scope
                break
        if id_field:
            break
    if not id_field:
        return None

    for scope in scopes:
        for k in NAME_KEYS:
            if k in scope and isinstance(scope[k], str):
                name_field = k
                break
        if name_field:
            break

    for scope in scopes:
        for k, v in scope.items():
            if TIME_KEY_RE.search(str(k)) and _looks_like_ts(v):
                time_field = k
                break
        if time_field:
            break

    return {"id_field": id_field, "name_field": name_field, "time_field": time_field}


def _candidate_score(entries, fields, path):
    """Rank a list-of-objects as 'the followers list', or return None if it does
    not plausibly qualify. The response holds several arrays that merely carry a
    viewer_id (directory_card_array, friend_list, recommend_list, ...); those are
    NOT the followers list and must be rejected so the bot says 'not found'
    rather than picking garbage. A candidate qualifies only if its path names it
    a 'follower' list OR its entries carry BOTH a last-login timestamp and a name
    (the real user-summary shape). Priority: follower-named >> timestamp >> name
    >> size."""
    pl = path.lower()
    is_follower = "follower" in pl
    has_time_and_name = bool(fields.get("time_field") and fields.get("name_field"))
    if not (is_follower or has_time_and_name):
        return None
    score = len(entries)
    if is_follower:
        score += 100000          # THE followers list (people who follow you)
    elif "friend" in pl or "follow" in pl:
        score += 20000
    if fields.get("time_field"):
        score += 40000           # has a usable last-login timestamp
    if fields.get("name_field"):
        score += 10000
    return score


def find_follower_list(decoded):
    """Return (entries, fields, path, score) for the best FOLLOWERS-list
    candidate in a decoded response, or (None, None, None, -1) if none qualify."""
    best = None  # (score, entries, fields, path)

    def walk(obj, path):
        nonlocal best
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
            fields = _entry_fields(obj[0])
            if fields:
                score = _candidate_score(obj, fields, path)
                if score is not None and (best is None or score > best[0]):
                    best = (score, obj, fields, path)
            walk(obj[0], path + "[]")

    walk(decoded, "")
    if best is None:
        return None, None, None, -1
    return best[1], best[2], best[3], best[0]


def extract_following_ids(decoded):
    """Set of viewer_ids YOU follow, read from friend_list-style arrays
    (friend_viewer_id + follow_time). Used to flag which followers are mutual,
    since the followers list itself carries no relationship flags. Excludes the
    recommend list and the followers list."""
    out = set()

    def walk(obj, path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
            pl = path.lower()
            if "friend" in pl and "recommend" not in pl and "follower" not in pl:
                for e in obj:
                    if not isinstance(e, dict):
                        continue
                    fid = e.get("friend_viewer_id") or e.get("viewer_id")
                    # you follow them if follow_time is a real timestamp (or the
                    # array carries no follow_time at all, i.e. a pure following list)
                    follows = _looks_like_ts(e.get("follow_time")) if "follow_time" in e else True
                    if isinstance(fid, int) and fid > 0 and follows:
                        out.add(fid)
            walk(obj[0], path + "[]")

    walk(decoded, "")
    return out


# --------------------------------------------------------------------------- #
# analyze                                                                      #
# --------------------------------------------------------------------------- #
def _headless_client():
    """Load cached auth (or capture once from the running game), then log in."""
    cfg = auth_capture.load_config()
    if not cfg or not cfg.get("auth_key"):
        print("[auth] No saved account -- capturing from the running game.")
        print("[auth] Have Umamusume at the HOME menu and tap around so it sends a request...")
        cfg = auth_capture.capture()
        auth_capture.save_config(cfg)
        print("[auth] Saved follower_data/account.json (game can be closed now).")
    client = uma_client.UmaClient(cfg)
    print(f"[auth] logging in as viewer {cfg.get('viewer_id')} ...")
    client.login(log=print)
    return client


def own_follow_num(decoded):
    """How many accounts the SERVER says you follow (friend/index own_follow_num).
    Used to sanity-check mutual detection: if the server says you follow people
    but we found zero follow-backs, mutual detection probably failed. None if
    the field isn't present."""
    data = decoded.get("data") if isinstance(decoded, dict) else None
    if isinstance(data, dict) and isinstance(data.get("own_follow_num"), int):
        return data["own_follow_num"]
    return None


def cmd_analyze(args):
    if args.days <= 0:
        print("[analyze] --days must be positive (e.g. 0.5 = 12 hours).")
        return
    os.makedirs(DATA_DIR, exist_ok=True)
    client = _headless_client()
    res = client.friend_index()
    entries, fields, p, _ = find_follower_list(res)
    if not entries:
        print("[analyze] friend/index returned no follower list.")
        return
    following = extract_following_ids(res)
    write_reports(entries, fields, p, None, days_to_label(args.days), following,
                  own_follow=own_follow_num(res))


def classify(entries, fields, threshold_seconds, following_ids=None):
    """Split entries into inactive/active by last-login age. `threshold_seconds`
    is the inactivity cutoff: last login older than this => inactive. Last-login
    values (unix ints OR 'YYYY-MM-DD HH:MM:SS' strings) are normalised to unix.
    `following_ids` marks followers you also follow back as mutual."""
    now = time.time()
    following_ids = following_ids or set()
    # Fail safe: a non-positive threshold (e.g. from `--days 0`/negative) would
    # put the cutoff at/after `now` and sweep essentially EVERYONE into inactive.
    # On a removal tool that's dangerous, so treat it as "nobody is inactive".
    if not threshold_seconds or threshold_seconds <= 0:
        threshold_seconds = float("inf")
    cutoff = now - threshold_seconds
    time_field = fields.get("time_field")
    inactive, active, unknown = [], [], []
    for e in entries:
        info = _entry_fields(e) or fields
        idf = info.get("id_field") or fields["id_field"]
        namef = info.get("name_field") or fields.get("name_field")
        timef = info.get("time_field") or time_field
        # resolve id/name/time possibly from a nested scope
        vid = _dig(e, idf)
        name = _dig(e, namef) if namef else None
        ts_raw = _dig(e, timef) if timef else None
        ts = _to_unix(ts_raw)   # normalised unix seconds, or None
        rel = _relationship(e)
        mutual = is_mutual(rel) or (vid in following_ids)
        row = {"viewer_id": vid, "name": name, "last_login": ts,
               "last_login_str": ts_raw if isinstance(ts_raw, str) else None,
               "days_inactive": round((now - ts) / 86400, 2) if ts is not None else None,
               "is_follower": rel["is_follower"], "is_follow": rel["is_follow"],
               "is_friend": rel["is_friend"], "mutual": mutual}
        if ts is None:
            unknown.append(row)
        elif ts < cutoff:
            inactive.append(row)
        else:
            active.append(row)
    inactive.sort(key=lambda r: r["last_login"] or 0)
    return inactive, active, unknown


def _dig(entry, key):
    """Fetch key from entry or a one-level-nested dict scope."""
    if not key or not isinstance(entry, dict):
        return None
    if key in entry:
        return entry[key]
    for v in entry.values():
        if isinstance(v, dict) and key in v:
            return v[key]
    return None


def _flag(entry, keys):
    """Resolve the first present relationship flag among `keys` to True/False/None
    (None = the field wasn't found, so we don't know)."""
    for k in keys:
        v = _dig(entry, k)
        if v is not None:
            return bool(v) if isinstance(v, bool) else v not in (0, "0", "", None)
    return None


def _relationship(entry):
    return {
        "is_follower": _flag(entry, REL_FOLLOWER_KEYS),
        "is_follow": _flag(entry, REL_FOLLOW_KEYS),
        "is_friend": _flag(entry, REL_FRIEND_KEYS),
    }


def is_mutual(rel):
    """True if we should treat this person as a mutual we must NOT auto-remove."""
    return bool(rel.get("is_follow")) or bool(rel.get("is_friend"))


def _all_rows(followers):
    """Every follower row from a persisted followers.json, regardless of bucket."""
    return (followers.get("inactive", []) + followers.get("active", [])
            + followers.get("unknown_last_login", []))


def reclassify_inactive(followers, threshold_seconds):
    """Recompute the inactive set from a persisted followers.json against a NEW
    threshold, using each row's stored `last_login`. Returns inactive rows
    (mutuals included), oldest-first. This is what makes the inactivity period
    authoritative at *removal* time, not just at scan time. A non-positive
    threshold returns nobody (fail safe, matching classify())."""
    if not threshold_seconds or threshold_seconds <= 0:
        return []
    now = time.time()
    cutoff = now - threshold_seconds
    # last_login is stored as a normalised unix number (classify did the parsing)
    out = [r for r in _all_rows(followers)
           if isinstance(r.get("last_login"), (int, float)) and r["last_login"] < cutoff]
    out.sort(key=lambda r: r.get("last_login") or 0)
    return out


# Removals act on last-login times FROZEN into followers.json at scan time. If
# that snapshot is stale, a follower may have logged in since yet still classify
# as inactive, and we'd remove them permanently by mistake. So removals refuse to
# run against an old scan and ask for a fresh one (a Scan re-fetches live data).
MAX_REMOVAL_SCAN_AGE = 1800.0  # seconds; ~30 min is ample to review a fresh scan


def scan_age_seconds(followers):
    """Seconds since this followers.json snapshot was captured, or None if the
    age is unknown (missing/invalid captured_ts)."""
    ts = followers.get("captured_ts")
    if not isinstance(ts, (int, float)) or ts <= 0:
        return None
    return max(0.0, time.time() - ts)


def scan_is_stale(followers):
    """True if the scan is too old (or of unknown age) to safely remove against."""
    age = scan_age_seconds(followers)
    return age is None or age > MAX_REMOVAL_SCAN_AGE


def mutual_detection_suspect(followers):
    """True when mutual detection likely FAILED: the server says you follow people
    (own_follow_num > 0) but the scan found zero follow-backs to cross-reference,
    so 'skip mutuals' would protect nobody. Fail loud rather than silently
    removing mutuals. Returns False when own_follow_num is unknown (older scans)."""
    own = followers.get("own_follow_num")
    return isinstance(own, int) and own > 0 and not followers.get("following_count")


def build_payload(entries, fields, path, template, period_label, following_ids=None,
                  own_follow=None):
    """Pure: classify the captured list into a report payload (no IO, no print).
    `period_label` is a dropdown-style string ('12 hours', '3 days', '1 month').
    `following_ids` = viewer_ids you follow, used to flag mutuals.
    `own_follow` = the server's own_follow_num, stored so removals can detect a
    likely mutual-detection failure (you follow people but 0 follow-backs found).
    Shared by the CLI and the UI so both agree on what 'inactive' means."""
    threshold_seconds = period_to_seconds(period_label)
    inactive, active, unknown = classify(entries, fields, threshold_seconds, following_ids)
    return {
        "captured_ts": time.time(),
        "captured_local": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_path": path,
        "detected_fields": fields,
        "period_label": period_label,
        "threshold_seconds": threshold_seconds,
        "days_threshold": round(threshold_seconds / 86400.0, 3),
        "total": len(entries),
        "following_count": len(following_ids or ()),
        "own_follow_num": own_follow,
        "inactive": inactive,
        "active": active,
        "unknown_last_login": unknown,
        "has_removal_template": bool(template),
    }


def render_report_md(payload):
    fields = payload["detected_fields"]
    inactive = payload["inactive"]
    period = payload.get("period_label", f"{payload.get('days_threshold', '?')} days")
    lines = [
        f"# Follower report  ({payload['captured_local']})",
        "",
        f"- Source: `{payload['source_path']}`",
        f"- Detected fields: id=`{fields['id_field']}`, "
        f"name=`{fields['name_field']}`, last_login=`{fields['time_field']}`",
        f"- Inactivity threshold: **{period}** (last login older than this)",
        f"- Followers seen: **{payload['total']}**  "
        f"(inactive: **{len(inactive)}**, active: {len(payload['active'])}, "
        f"unknown last-login: {len(payload['unknown_last_login'])})",
        "",
        f"## Inactive followers (inactive ≥ {period}) — removal candidates",
        "",
    ]
    no_time = fields["time_field"] is None
    if no_time and not inactive:
        lines.append("> ⚠️ No last-login timestamp field was detected, so inactivity "
                     "can't be computed. No removal candidates are listed; refine "
                     "`TIME_KEY_RE` in the script or pick targets manually.\n")
    n_mutual = sum(1 for r in inactive if r.get("mutual"))
    if n_mutual:
        lines.append(f"> ℹ️ {n_mutual} of these are **mutual** (you follow them / friends). "
                     "Removals skip mutuals by default — override with `--include-mutual` "
                     "(CLI) or the *Skip mutuals* toggle (UI).\n")
    if inactive:
        lines.append("| viewer_id | name | days inactive | mutual? |")
        lines.append("|---|---|---|---|")
        for r in inactive:
            mut = "⚠️ mutual" if r.get("mutual") else ""
            lines.append(f"| {r['viewer_id']} | {r['name'] or ''} | {r['days_inactive']} | {mut} |")
    elif no_time:
        lines.append("_Inactivity could not be computed (no last-login field detected)._")
    else:
        lines.append("_None — every follower is within the threshold._")
    lines.append("")
    return "\n".join(lines)


def save_reports(payload, template):
    """Write followers.json + followers_report.md (+ unfollow_template.json)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "followers.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    if template:
        with open(os.path.join(DATA_DIR, "unfollow_template.json"), "w", encoding="utf-8") as f:
            json.dump(template, f, ensure_ascii=False, indent=2)
    with open(os.path.join(DATA_DIR, "followers_report.md"), "w", encoding="utf-8") as f:
        f.write(render_report_md(payload))
    return DATA_DIR


def write_reports(entries, fields, path, template, period_label, following_ids=None,
                  own_follow=None):
    """CLI convenience: build + save + print a short summary."""
    payload = build_payload(entries, fields, path, template, period_label,
                            following_ids, own_follow=own_follow)
    save_reports(payload, template)
    inactive = payload["inactive"]
    print(f"\n[analyze] wrote follower_data/followers.json + followers_report.md")
    print(f"[analyze] {len(inactive)} inactive follower(s) beyond {period_label}.")
    if inactive:
        preview = ", ".join(str(r["viewer_id"]) for r in inactive[:10])
        print(f"[analyze] candidates: {preview}{' ...' if len(inactive) > 10 else ''}")
    return payload


# --------------------------------------------------------------------------- #
# run                                                                          #
# --------------------------------------------------------------------------- #
def cmd_run(args):
    fj = os.path.join(DATA_DIR, "followers.json")
    if not os.path.exists(fj):
        print("[run] follower_data/followers.json not found. Run "
              "`python unfollower_bot.py analyze --days N` first.")
        return
    if args.days <= 0:
        print("[run] --days must be positive (e.g. 0.5 = 12 hours).")
        return
    if args.max < 0:
        print("[run] --max cannot be negative (0 = all, or a positive cap).")
        return
    with open(fj, encoding="utf-8") as f:
        followers = json.load(f)
    inactive = reclassify_inactive(followers, args.days * 86400.0)
    candidates = [r for r in inactive if r.get("viewer_id")]
    if not args.include_mutual:
        candidates = [r for r in candidates if not r.get("mutual")]
        if mutual_detection_suspect(followers):
            print(f"[run] WARNING: the server says you follow "
                  f"{followers.get('own_follow_num')} account(s) but the last scan "
                  "found 0 follow-backs, so mutual detection likely failed and "
                  "'skip mutuals' may protect nobody. Re-scan before removing.")
    cap = None if args.max == 0 else args.max          # 0 / unset = all
    targets = [r["viewer_id"] for r in candidates][:cap]
    print(f"[run] period {days_to_label(args.days)}: {len(inactive)} inactive; "
          f"removing {len(targets)}{'' if cap is None else f' (max {cap})'}.")
    if not targets:
        print("[run] nothing to remove.")
        return
    if not (args.arm and args.yes):
        print("[run] DRY RUN -- nothing sent. Add --arm --yes to actually remove.")
        return
    if scan_is_stale(followers):
        age = scan_age_seconds(followers)
        age_txt = "of unknown age" if age is None else f"{age / 60:.0f} min old"
        print(f"[run] the last scan is {age_txt}; removals must run against a fresh "
              "scan so nobody who logged in since is removed by mistake. Re-run "
              "`python unfollower_bot.py analyze --days N`, then this command again.")
        return
    client = _headless_client()
    removed = 0
    for i, t in enumerate(targets):
        try:
            client.un_follower(t)
            removed += 1
            print(f"[run] removed viewer_id {t}  ({removed}/{len(targets)})")
        except Exception as e:
            print(f"[run] failed to remove {t}: {e} -- stopping.")
            break
        if i < len(targets) - 1:
            time.sleep(max(0.5, args.delay))
    print(f"[run] done. removed {removed} follower(s). Re-scan to confirm.")


# =========================================================================== #
# Dashboard UI (clean / minimalist / dark, matching the Icarus family)         #
# =========================================================================== #
UI_FONT = "Segoe UI"
MONO_FONT = "Consolas"
BG        = "#0b0b0d"   # window canvas
PANEL     = "#141417"   # card surface
PANEL_HI  = "#1c1c21"   # hover / input
BORDER    = "#26262c"   # hairline
FG        = "#f4f4f6"   # primary text
FG_DIM    = "#9a9aa4"   # secondary text
FG_FAINT  = "#5c5c66"   # captions
ACCENT    = "#a6e15a"   # lime green (from the reference dashboard)
ACCENT_DK = "#26301a"   # accent fill wash
DANGER    = "#ff6b6b"
WARN      = "#e0a86a"

# (inactivity period options live near the top: PERIOD_OPTIONS / PERIOD_DEFAULT)


def load_logo(target_px=26):
    """Return (PhotoImage, True) for the Icarus artwork if present, else
    (None, False). Prefers Pillow for a crisp downscale. Needs a Tk root."""
    # search next to the exe, in the source dir, and in the PyInstaller (_MEIPASS)
    # bundle dir so a single-file exe can carry the logo inside it.
    meipass = getattr(sys, "_MEIPASS", None)
    roots = [os.path.join(BASE_DIR, "assets"), BASE_DIR, os.getcwd()]
    if meipass:
        roots += [os.path.join(meipass, "assets"), meipass]
    cands = []
    for root in roots:
        cands += sorted(glob.glob(os.path.join(root, "[Ii]carus*.png")))
        cands.append(os.path.join(root, "icarus.png"))
    for p in cands:
        if not os.path.exists(p):
            continue
        try:
            from PIL import Image, ImageTk
            im = Image.open(p).convert("RGBA")
            im.thumbnail((target_px, target_px), Image.LANCZOS)
            return ImageTk.PhotoImage(im), True
        except Exception:
            pass
        try:
            img = tk.PhotoImage(file=p)
            factor = max(1, round(max(img.width(), img.height()) / target_px))
            if factor > 1:
                img = img.subsample(factor, factor)
            return img, True
        except Exception:
            pass
    return None, False


class RoundedButton(tk.Canvas):
    """Minimalist pill button drawn on a canvas; doubles as a toggle chip."""

    def __init__(self, parent, text="", command=None, width=170, height=32,
                 radius=16, fill=PANEL, hover=PANEL_HI, fg=FG, border=BORDER,
                 active_fill=ACCENT_DK, active_fg=ACCENT, active_border=ACCENT,
                 font=(UI_FONT, 9, "bold"), bg=BG):
        super().__init__(parent, width=width, height=height, bg=bg,
                         highlightthickness=0, bd=0)
        self.cw, self.ch, self.rad = width, height, radius
        self.pal = {"fill": fill, "hover": hover, "fg": fg, "border": border,
                    "afill": active_fill, "afg": active_fg, "aborder": active_border}
        self._font, self._text, self.command = font, text, command
        self.active = False
        self.enabled = True
        self._hovering = False
        self.configure(cursor="hand2")
        self._render()
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._click)

    def _click(self, _e):
        if self.enabled and self.command:
            self.command()

    def _on_enter(self, _e):
        self._hovering = True
        self._render()

    def _on_leave(self, _e):
        self._hovering = False
        self._render()

    def _render(self):
        self.delete("all")
        p = self.pal
        if self.active:
            fill, fg, border = p["afill"], p["afg"], p["aborder"]
        else:
            fill, fg, border = p["fill"], p["fg"], p["border"]
        if self._hovering and self.enabled:
            fill = p["afill"] if self.active else p["hover"]
        if not self.enabled:
            fg, border = FG_FAINT, BORDER
        x1, y1, x2, y2, r = 1, 1, self.cw - 1, self.ch - 1, self.rad
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
               x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        self.create_polygon(pts, smooth=True, splinesteps=24, fill=fill, outline=border)
        self.create_text(self.cw / 2, self.ch / 2, text=self._text, fill=fg, font=self._font)

    def set_text(self, text):
        self._text = text
        self._render()

    def set_active(self, active):
        self.active = bool(active)
        self._render()

    def set_enabled(self, enabled):
        self.enabled = bool(enabled)
        self.configure(cursor="hand2" if enabled else "arrow")
        self._render()


class Dropdown(tk.Canvas):
    """A themed dropdown: a pill showing the current value + chevron; clicking
    opens a small dark popup list. Built custom so it matches the dark theme."""

    def __init__(self, parent, values, default=None, command=None,
                 width=180, height=32, font=(UI_FONT, 9)):
        super().__init__(parent, width=width, height=height, bg=BG,
                         highlightthickness=0, bd=0)
        self.values = list(values)
        self.value = default if default in self.values else self.values[0]
        self.command = command
        self.cw, self.ch, self.rad = width, height, height // 2
        self._font = font
        self._hover = False
        self._popup = None
        self.configure(cursor="hand2")
        self._render()
        self.bind("<Enter>", lambda e: (setattr(self, "_hover", True), self._render()))
        self.bind("<Leave>", lambda e: (setattr(self, "_hover", False), self._render()))
        self.bind("<Button-1>", lambda e: self._toggle())

    def _render(self):
        self.delete("all")
        fill = PANEL_HI if self._hover else PANEL
        x1, y1, x2, y2, r = 1, 1, self.cw - 1, self.ch - 1, self.rad
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
               x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        self.create_polygon(pts, smooth=True, splinesteps=24, fill=fill, outline=BORDER)
        self.create_text(14, self.ch / 2, text=self.value, fill=FG, font=self._font, anchor="w")
        cx = self.cw - 16
        cy = self.ch / 2
        self.create_line(cx - 4, cy - 2, cx, cy + 2, fill=FG_DIM, width=2)
        self.create_line(cx + 4, cy - 2, cx, cy + 2, fill=FG_DIM, width=2)

    def set_value(self, v):
        self.value = v
        self._render()

    def _toggle(self):
        if self._popup is not None:
            self._close()
        else:
            self._open()

    def _open(self):
        self._popup = tk.Toplevel(self)
        self._popup.overrideredirect(True)
        self._popup.attributes("-topmost", True)
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.ch + 3
        frame = tk.Frame(self._popup, bg=PANEL, highlightbackground=BORDER,
                         highlightthickness=1, bd=0)
        frame.pack(fill="both", expand=True)
        for v in self.values:
            lbl = tk.Label(frame, text=v, bg=PANEL, fg=FG if v != self.value else ACCENT,
                           font=self._font, anchor="w", padx=14, pady=6)
            lbl.pack(fill="x")
            lbl.bind("<Enter>", lambda e, w=lbl: w.configure(bg=PANEL_HI))
            lbl.bind("<Leave>", lambda e, w=lbl: w.configure(bg=PANEL))
            lbl.bind("<Button-1>", lambda e, val=v: self._select(val))
        # size the popup to its actual content so no row is clipped, whatever the
        # option count or display scaling
        self._popup.update_idletasks()
        h = frame.winfo_reqheight()
        self._popup.geometry(f"{self.cw}x{h}+{x}+{y}")
        self._popup.bind("<FocusOut>", lambda e: self._close())
        self._popup.bind("<Escape>", lambda e: self._close())
        self._popup.focus_force()

    def _select(self, v):
        self.set_value(v)
        self._close()
        if self.command:
            self.command(v)

    def _close(self):
        if self._popup is not None:
            try:
                self._popup.destroy()
            except Exception:
                pass
            self._popup = None


def dark_entry(parent, textvariable, width=6):
    return tk.Entry(parent, textvariable=textvariable, width=width, bg=PANEL_HI,
                    fg=FG, insertbackground=FG, relief="flat", justify="center",
                    highlightthickness=1, highlightbackground=BORDER,
                    highlightcolor=ACCENT, font=(UI_FONT, 10))


def sidebar_label(parent, text):
    return tk.Label(parent, text=text, fg=FG_FAINT, bg=PANEL,
                    font=(UI_FONT, 8, "bold"))


class BotController:
    """Runs analyze/run on a background thread and reports progress to the UI
    through a single `emit(dict)` sink (drained on the Tk thread)."""

    def __init__(self, emit):
        self.emit = emit
        self._thread = None
        self._stop = threading.Event()
        self._hook = None

    # -- progress sink helpers --
    def log(self, msg, level="info"):
        self.emit({"kind": "log", "level": level, "msg": msg})

    def status(self, color, text):
        self.emit({"kind": "status", "color": color, "text": text})

    def stats(self, data):
        self.emit({"kind": "stats", "data": data})

    def busy(self, on):
        self.emit({"kind": "busy", "on": on})

    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def stop(self):
        if self.running():
            self._stop.set()
            self.log("Stop requested — finishing current step…", "warn")

    def start_analyze(self, period_label):
        if self.running():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._analyze, args=(period_label,), daemon=True)
        self._thread.start()

    def start_run(self, opts):
        if self.running():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(opts,), daemon=True)
        self._thread.start()

    def _sleep_human(self, lo, hi):
        """Wait a randomized, human-like interval (interruptible)."""
        lo = max(0.0, lo)
        hi = max(lo, hi)
        total = random.uniform(lo, hi)
        self.log(f"…waiting {total:.1f}s before next action (human-like)")
        steps = max(1, int(total / 0.1))
        for _ in range(steps):
            if self._stop.is_set():
                return False
            time.sleep(0.1)
        return not self._stop.is_set()

    def _emit_payload_stats(self, payload):
        inactive = payload["inactive"]
        mutual = sum(1 for r in inactive if r.get("mutual"))
        self.stats({"followers": payload["total"], "inactive": len(inactive),
                    "mutual": mutual})

    def _get_client(self):
        """Load cached auth (or capture it once off the running game), then log
        in to the server. Returns a live UmaClient. The game is only needed for
        the one-time auth capture; after that everything is headless."""
        cfg = auth_capture.load_config()
        if not cfg or not cfg.get("auth_key"):
            self.status(WARN, "capturing auth")
            self.log("First run: capturing your account auth from the game.", "warn")
            self.log("Make sure Umamusume is at the HOME menu, then tap around a "
                     "little so it sends a request…", "warn")
            cfg = auth_capture.capture(log=lambda m: self.log(m, "info"))
            auth_capture.save_config(cfg)
            self.log("Auth captured & saved — the game can be closed from now on.", "ok")
        client = uma_client.UmaClient(cfg)
        self.status(ACCENT, "login")
        self.log(f"Logging in to the server as viewer {cfg.get('viewer_id')} …")
        client.login(log=lambda m: self.log(m, "info"))
        self.log("Login OK — talking to the game server directly.", "ok")
        return client

    def _analyze(self, period_label):
        try:
            self.busy(True)
            self.status(WARN, "connecting")
            client = self._get_client()
            self.status(ACCENT, "scanning")
            res = client.friend_index(log=lambda m: self.log(m, "info"))
            entries, fields, p, _ = find_follower_list(res)
            if not entries:
                self.log("friend/index returned no follower list (keys: "
                         + str(list((res.get('data') or {}).keys())) + ").", "err")
                self.status(DANGER, "no data")
                return
            following = extract_following_ids(res)
            payload = build_payload(entries, fields, p, None, period_label, following,
                                    own_follow=own_follow_num(res))
            save_reports(payload, None)
            self._emit_payload_stats(payload)
            n_mut = sum(1 for r in payload["inactive"] if r.get("mutual"))
            self.log(f"Followers: {payload['total']} · inactive ≥ {period_label}: "
                     f"{len(payload['inactive'])} (mutual: {n_mut}). "
                     "Set Arm + Max, then Remove inactive.", "ok")
            self.status(FG_FAINT, "idle")
        except frida.ProcessNotFoundError:
            self.log("Umamusume isn't running — needed once to capture auth. Start it, "
                     "reach the home menu, then Scan.", "err")
            self.status(DANGER, "no game")
        except Exception as e:
            self.log(f"Error: {e}", "err")
            self.status(DANGER, "error")
        finally:
            self.busy(False)

    def _run(self, opts):
        try:
            self.busy(True)
            fj = os.path.join(DATA_DIR, "followers.json")
            if not os.path.exists(fj):
                self.log("No scan on file. Click Scan followers first.", "err")
                self.status(DANGER, "no data")
                return
            with open(fj, encoding="utf-8") as f:
                followers = json.load(f)
            # Re-derive the inactive set against the CURRENTLY selected period.
            period = opts.get("period") or followers.get("period_label", "?")
            inactive = reclassify_inactive(followers, period_to_seconds(period))
            candidates = [r for r in inactive if r.get("viewer_id")]
            skipped = 0
            if not opts["include_mutual"]:
                before = len(candidates)
                candidates = [r for r in candidates if not r.get("mutual")]
                skipped = before - len(candidates)
            targets = [r["viewer_id"] for r in candidates][: opts["max_n"]]
            cap_txt = "no cap" if opts["max_n"] is None else f"cap {opts['max_n']}"
            self.log(f"{len(inactive)} inactive · {len(candidates)} after mutual "
                     f"filter · removing {len(targets)} ({cap_txt}).")
            if skipped:
                self.log(f"Skipping {skipped} mutual follower(s) — toggle 'Skip mutuals' off to include.", "info")
            if not targets:
                self.log("Nothing to remove with the current settings.", "warn")
                self.status(FG_FAINT, "idle")
                return

            if not opts["arm"]:
                for t in targets:
                    self.log(f"[dry-run] would remove viewer_id {t}")
                self.log("DRY RUN — nothing sent. Turn on 'Arm removals' to actually "
                         "remove (start with Max = 1 to validate).", "warn")
                self.status(FG_FAINT, "idle")
                return

            # Safety net (the UI also gates this in _on_remove): never remove
            # against a stale snapshot — last-login times could be out of date.
            if scan_is_stale(followers):
                age = scan_age_seconds(followers)
                age_txt = "of unknown age" if age is None else f"{age / 60:.0f} min old"
                self.log(f"Refusing to remove: the scan is {age_txt}. Click Scan "
                         "followers again so removals act on fresh last-login data.",
                         "err")
                self.status(DANGER, "stale scan")
                return

            self.status(WARN, "connecting")
            client = self._get_client()
            self.status(ACCENT, "removing")
            removed = 0
            for i, t in enumerate(targets):
                if self._stop.is_set():
                    break
                try:
                    client.un_follower(t, log=lambda m: self.log(m, "info"))
                    removed += 1
                    self.stats({"removed": removed})
                    self.log(f"Removed viewer_id {t}   ({removed}/{len(targets)})", "ok")
                except Exception as e:
                    self.log(f"Failed to remove {t}: {e} — stopping.", "err")
                    break
                if i < len(targets) - 1 and not self._sleep_human(opts["delay_min"], opts["delay_max"]):
                    break
            self.log(f"Done — removed {removed} follower(s) via the server. "
                     "Re-scan to confirm the new count.", "ok")
            self.status(FG_FAINT, "idle")
        except frida.ProcessNotFoundError:
            self.log("Umamusume isn't running — needed once to capture auth.", "err")
            self.status(DANGER, "no game")
        except Exception as e:
            self.log(f"Error: {e}", "err")
            self.status(DANGER, "error")
        finally:
            self.busy(False)


class UnfollowerUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.overrideredirect(True)
        self.configure(bg=BG)
        w, h = 940, 600
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 3}")

        # taskbar presence + rounded corners on Win11 (same trick as the recorder)
        try:
            import ctypes
            hwnd = self.winfo_id()
            parent = ctypes.windll.user32.GetParent(hwnd)
            if parent:
                style = ctypes.windll.user32.GetWindowLongW(parent, -20)
                style = (style & ~0x00000080) | 0x00040000
                ctypes.windll.user32.SetWindowLongW(parent, -20, style)
                ctypes.windll.user32.SetWindowPos(parent, 0, 0, 0, 0, 0, 0x0027)
                try:
                    ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        parent, 33, ctypes.byref(ctypes.c_int(2)), 4)
                except Exception:
                    pass
        except Exception:
            pass

        self.ui_queue = queue.Queue()
        self.controller = BotController(self.ui_queue.put)
        self._busy = False
        self.aot = False

        self._build_titlebar()
        self._build_body()
        self.after(80, self._poll)
        self._log("Ready. Start the game, open your follower list, then Scan.", "head")
        # if a prior scan is on file, reflect it in the cards for the current period
        self._refresh_cards_from_file(announce=True)

    # ---- title bar --------------------------------------------------------
    def _build_titlebar(self):
        bar = tk.Frame(self, bg=BG, height=40)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        brand = tk.Frame(bar, bg=BG)
        brand.pack(side="left", padx=14)
        self._logo_img, has = load_logo(26)
        if has:
            logo = tk.Label(brand, image=self._logo_img, bg=BG)
            try:
                self.iconphoto(True, self._logo_img)
            except Exception:
                pass
        else:
            logo = tk.Label(brand, text="🪽", bg=BG, fg=ACCENT, font=(UI_FONT, 13))
        logo.pack(side="left", pady=(3, 0))
        tk.Label(brand, text=APP_NAME, fg=FG, bg=BG,
                 font=(UI_FONT, 11, "bold")).pack(side="left", padx=(9, 8))
        self.status_dot = tk.Canvas(brand, width=9, height=9, bg=BG,
                                    highlightthickness=0, bd=0)
        self._dot = self.status_dot.create_oval(1, 1, 8, 8, fill=FG_FAINT, outline="")
        self.status_dot.pack(side="left", pady=(3, 0))
        self.status_lbl = tk.Label(brand, text="idle", fg=FG_FAINT, bg=BG,
                                   font=(UI_FONT, 8))
        self.status_lbl.pack(side="left", padx=(5, 0))

        close = tk.Label(bar, text="✕", fg=FG_FAINT, bg=BG, font=(UI_FONT, 11),
                         width=3, cursor="hand2")
        close.pack(side="right")
        close.bind("<Button-1>", lambda e: self.destroy())
        close.bind("<Enter>", lambda e: close.configure(fg=DANGER))
        close.bind("<Leave>", lambda e: close.configure(fg=FG_FAINT))
        mini = tk.Label(bar, text="—", fg=FG_FAINT, bg=BG, font=(UI_FONT, 11),
                        width=3, cursor="hand2")
        mini.pack(side="right")
        mini.bind("<Button-1>", lambda e: (self.overrideredirect(False), self.iconify()))

        # clearly-labelled "stay on top" toggle (was a cryptic ⇧ icon); it lights
        # up green when active so the window's pinned state is obvious.
        self.btn_aot = RoundedButton(bar, text="📌 Stay on top", command=self._toggle_aot,
                                     width=116, height=26, radius=13, bg=BG,
                                     active_fill=ACCENT_DK, active_fg=ACCENT, active_border=ACCENT)
        self.btn_aot.pack(side="right", padx=(0, 8), pady=7)

        # join-the-Discord button (Discord blurple)
        btn_discord = RoundedButton(bar, text="✦ Discord", width=90, height=26, radius=13,
                                    command=lambda: webbrowser.open(DISCORD_URL), bg=BG,
                                    fg="#8b97f0", border="#3a3f6b", hover="#20233a",
                                    active_fill="#20233a", active_fg="#aab4f7", active_border=DISCORD_BLURPLE)
        btn_discord.pack(side="right", padx=(0, 6), pady=7)

        for w in (bar, brand):
            w.bind("<Button-1>", self._start_move)
            w.bind("<B1-Motion>", self._do_move)

    def _start_move(self, e):
        self._dx, self._dy = e.x, e.y

    def _do_move(self, e):
        self.geometry(f"+{self.winfo_x() + e.x - self._dx}+{self.winfo_y() + e.y - self._dy}")

    def _toggle_aot(self):
        self.aot = not self.aot
        self.attributes("-topmost", self.aot)
        self.btn_aot.set_active(self.aot)
        self.btn_aot.set_text("📌 On top: ON" if self.aot else "📌 Stay on top")

    # ---- body -------------------------------------------------------------
    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_sidebar(body)
        self._build_main(body)

    def _build_sidebar(self, parent):
        side = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1, width=248)
        side.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        side.grid_propagate(False)

        pad = 16
        sidebar_label(side, "CONTROLS").pack(anchor="w", padx=pad, pady=(16, 10))

        sidebar_label(side, "INACTIVITY PERIOD").pack(anchor="w", padx=pad, pady=(2, 4))
        self.dd_period = Dropdown(side, PERIOD_OPTIONS, default=PERIOD_DEFAULT,
                                  width=248 - 2 * pad, command=self._on_period_change)
        self.dd_period.pack(anchor="w", padx=pad)

        sidebar_label(side, "DELAY BETWEEN ACTIONS (SECONDS)").pack(anchor="w", padx=pad, pady=(16, 4))
        delay_row = tk.Frame(side, bg=PANEL)
        delay_row.pack(anchor="w", padx=pad, fill="x")
        self.var_dmin = tk.StringVar(value="4")
        self.var_dmax = tk.StringVar(value="12")
        dark_entry(delay_row, self.var_dmin, width=5).pack(side="left")
        tk.Label(delay_row, text="to", fg=FG_DIM, bg=PANEL,
                 font=(UI_FONT, 9)).pack(side="left", padx=8)
        dark_entry(delay_row, self.var_dmax, width=5).pack(side="left")
        tk.Label(delay_row, text="sec", fg=FG_FAINT, bg=PANEL,
                 font=(UI_FONT, 8)).pack(side="left", padx=(6, 0))
        tk.Label(side, text="randomized each time to mimic a human",
                 fg=FG_FAINT, bg=PANEL, font=(UI_FONT, 8)).pack(anchor="w", padx=pad, pady=(4, 0))

        sidebar_label(side, "MAX REMOVALS PER RUN").pack(anchor="w", padx=pad, pady=(16, 4))
        self.var_max = tk.StringVar(value="all")
        dark_entry(side, self.var_max, width=7).pack(anchor="w", padx=pad)
        tk.Label(side, text="'all' clears everyone inactive; or type a number",
                 fg=FG_FAINT, bg=PANEL, font=(UI_FONT, 8)).pack(anchor="w", padx=pad, pady=(4, 0))

        opt_row = tk.Frame(side, bg=PANEL)
        opt_row.pack(anchor="w", padx=pad, pady=(16, 0), fill="x")
        self.chip_mutual = RoundedButton(opt_row, text="Skip mutuals", width=104,
                                         height=28, radius=14, bg=PANEL,
                                         command=lambda: self.chip_mutual.set_active(
                                             not self.chip_mutual.active))
        self.chip_mutual.set_active(True)
        self.chip_mutual.pack(side="left")
        self.chip_arm = RoundedButton(opt_row, text="Arm removals", width=104,
                                      height=28, radius=14, bg=PANEL,
                                      active_fill="#3a1c1c", active_fg=DANGER,
                                      active_border=DANGER,
                                      command=lambda: self.chip_arm.set_active(
                                          not self.chip_arm.active))
        self.chip_arm.pack(side="left", padx=(8, 0))

        tk.Frame(side, bg=BORDER, height=1).pack(fill="x", padx=pad, pady=(18, 14))

        self.btn_scan = RoundedButton(side, text="⟳  Scan followers", width=248 - 2 * pad,
                                      height=38, radius=19, command=self._on_scan,
                                      bg=PANEL, active_fill=ACCENT_DK,
                                      fg=ACCENT, border=ACCENT)
        self.btn_scan.pack(padx=pad, pady=(0, 10))
        self.btn_remove = RoundedButton(side, text="Remove inactive", width=248 - 2 * pad,
                                        height=38, radius=19, command=self._on_remove,
                                        bg=PANEL, fg=DANGER, border=BORDER,
                                        hover="#241416")
        self.btn_remove.pack(padx=pad)
        self.btn_stop = RoundedButton(side, text="Stop", width=248 - 2 * pad,
                                      height=30, radius=15, command=self._on_stop,
                                      bg=PANEL)
        self.btn_stop.pack(padx=pad, pady=(10, 0))
        self.btn_stop.set_enabled(False)

    def _build_main(self, parent):
        main = tk.Frame(parent, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        cards = tk.Frame(main, bg=BG)
        cards.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        for i in range(4):
            cards.columnconfigure(i, weight=1)
        self.card_vals = {}
        for i, (key, cap) in enumerate([("followers", "FOLLOWERS"),
                                        ("inactive", "INACTIVE"),
                                        ("mutual", "MUTUAL · KEPT"),
                                        ("removed", "REMOVED")]):
            card = tk.Frame(cards, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0))
            tk.Label(card, text=cap, fg=FG_FAINT, bg=PANEL,
                     font=(UI_FONT, 8, "bold")).pack(anchor="w", padx=14, pady=(12, 0))
            accent = ACCENT if key == "inactive" else (DANGER if key == "removed" else FG)
            val = tk.Label(card, text="—", fg=accent, bg=PANEL, font=(UI_FONT, 22, "bold"))
            val.pack(anchor="w", padx=14, pady=(0, 12))
            self.card_vals[key] = val

        logcard = tk.Frame(main, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        logcard.grid(row=1, column=0, sticky="nsew")
        head = tk.Frame(logcard, bg=PANEL)
        head.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(head, text="ACTIVITY LOG", fg=FG_FAINT, bg=PANEL,
                 font=(UI_FONT, 8, "bold")).pack(side="left")
        tk.Label(head, text="detailed", fg=FG_FAINT, bg=PANEL,
                 font=(UI_FONT, 8)).pack(side="right")

        text_wrap = tk.Frame(logcard, bg=PANEL)
        text_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        sb = tk.Scrollbar(text_wrap, width=10)
        sb.pack(side="right", fill="y")
        self.txt = tk.Text(text_wrap, bg="#0e0e11", fg=FG_DIM, relief="flat", bd=0,
                           font=(MONO_FONT, 9), wrap="word", padx=12, pady=10,
                           yscrollcommand=sb.set, highlightthickness=0,
                           insertbackground=FG, state="disabled")
        self.txt.pack(side="left", fill="both", expand=True)
        sb.config(command=self.txt.yview)
        self.txt.tag_config("ts", foreground=FG_FAINT)
        self.txt.tag_config("info", foreground=FG_DIM)
        self.txt.tag_config("ok", foreground=ACCENT)
        self.txt.tag_config("warn", foreground=WARN)
        self.txt.tag_config("err", foreground=DANGER)
        self.txt.tag_config("head", foreground=FG)

    # ---- actions ----------------------------------------------------------
    def _read_period(self):
        return self.dd_period.value

    def _on_period_change(self, _value):
        """Changing the period live-updates the cards from the last scan, so the
        INACTIVE count always matches what Remove would act on."""
        if not self._busy:
            self._refresh_cards_from_file()

    def _load_scan(self):
        """Load the persisted followers.json, or None if absent/unreadable."""
        fj = os.path.join(DATA_DIR, "followers.json")
        if not os.path.exists(fj):
            return None
        try:
            with open(fj, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _refresh_cards_from_file(self, announce=False):
        """Populate the stat cards from a persisted followers.json, reclassified
        against the currently selected period. No-op if there's no scan on file."""
        followers = self._load_scan()
        if followers is None:
            return
        inactive = reclassify_inactive(followers, period_to_seconds(self._read_period()))
        total = followers.get("total", len(_all_rows(followers)))
        mutual = sum(1 for r in inactive if r.get("mutual"))
        self.card_vals["followers"].configure(text=str(total))
        self.card_vals["inactive"].configure(text=str(len(inactive)))
        self.card_vals["mutual"].configure(text=str(mutual))
        if announce:
            self._log(f"Loaded prior scan from {followers.get('captured_local', '?')}. "
                      f"Cards reflect the selected period; re-scan to refresh.", "info")

    def _read_float(self, var, default):
        try:
            return max(0.0, float(var.get()))
        except Exception:
            return default

    def _read_max(self):
        """Return the per-run cap, or None for 'no cap' (blank / 'all' / 0)."""
        v = (self.var_max.get() or "").strip().lower()
        if v in ("", "all", "0"):
            return None
        try:
            return max(1, int(float(v)))
        except Exception:
            return None

    def _pending_removal_count(self):
        """(count that would be removed, total inactive candidates) for the
        confirm dialog — mirrors what _run computes."""
        followers = self._load_scan()
        if followers is None:
            return 0, 0
        inactive = reclassify_inactive(followers, period_to_seconds(self._read_period()))
        cands = [r for r in inactive if r.get("viewer_id")]
        if self.chip_mutual.active:
            cands = [r for r in cands if not r.get("mutual")]
        mx = self._read_max()
        return (len(cands) if mx is None else min(len(cands), mx)), len(cands)

    def _on_scan(self):
        if self._busy:
            return
        for k in ("followers", "inactive", "mutual", "removed"):
            self.card_vals[k].configure(text="—")
        self.controller.start_analyze(self._read_period())

    def _on_remove(self):
        if self._busy:
            return
        self.card_vals["removed"].configure(text="—")
        dmin = self._read_float(self.var_dmin, 4.0)
        dmax = self._read_float(self.var_dmax, 12.0)
        if dmax < dmin:
            dmin, dmax = dmax, dmin
        period = self._read_period()
        opts = {
            "period": period,
            "delay_min": dmin,
            "delay_max": dmax,
            "max_n": self._read_max(),   # None = remove all inactive
            "include_mutual": not self.chip_mutual.active,
            "arm": self.chip_arm.active,
        }
        if opts["arm"]:
            followers = self._load_scan()
            if followers is None:
                messagebox.showwarning(
                    APP_SHORT, "No scan on file yet — click Scan followers first.")
                return
            # Removals act on last-login times captured at scan time; block if that
            # snapshot is stale so nobody who logged in since is removed by mistake.
            if scan_is_stale(followers):
                age = scan_age_seconds(followers)
                age_txt = "of unknown age" if age is None else f"{int(age // 60)} min old"
                messagebox.showwarning(
                    APP_SHORT,
                    f"The last scan is {age_txt}. To avoid removing someone who has "
                    "logged in since, click Scan followers again, then Remove.")
                return
            count, total = self._pending_removal_count()
            est_min = round(count * (dmin + dmax) / 2 / 60, 1)
            age = scan_age_seconds(followers)
            age_txt = ("just now" if (age is not None and age < 60)
                       else "unknown" if age is None else f"{int(age // 60)} min ago")
            warn_line = ""
            if not opts["include_mutual"] and mutual_detection_suspect(followers):
                warn_line = ("⚠️ Mutual detection looks unreliable (server says you "
                             f"follow {followers.get('own_follow_num')} but 0 follow-backs "
                             "were found) — mutuals may NOT be protected.\n")
            if not messagebox.askyesno(
                    APP_SHORT,
                    f"Arm is ON — this permanently removes followers via the server.\n\n"
                    f"Inactivity period: {period}\n"
                    f"Scanned: {age_txt}\n"
                    f"Will remove: {count} of {total} inactive"
                    f"{' (capped)' if opts['max_n'] is not None else ' (ALL)'}\n"
                    f"{'Skipping' if not opts['include_mutual'] else 'INCLUDING'} mutuals\n"
                    f"Pacing: {dmin:g}-{dmax:g}s each  (~{est_min} min total)\n"
                    f"{warn_line}\n"
                    "You can press Stop any time. Continue?",
                    default=messagebox.NO, icon=messagebox.WARNING):
                return
        self.controller.start_run(opts)

    def _on_stop(self):
        self.controller.stop()

    def _set_busy(self, on):
        was = self._busy
        self._busy = on
        self.btn_scan.set_enabled(not on)
        self.btn_remove.set_enabled(not on)
        self.btn_stop.set_enabled(on)
        # When a scan/run finishes, resync the cards to the CURRENT period so the
        # INACTIVE count always matches what Remove would act on -- even if the
        # period was changed mid-scan (period changes are ignored while busy).
        if was and not on:
            self._refresh_cards_from_file()

    def _log(self, msg, level="info"):
        self.txt.configure(state="normal")
        self.txt.insert("end", f"{time.strftime('%H:%M:%S')}  ", ("ts",))
        self.txt.insert("end", msg + "\n", (level,))
        self.txt.see("end")
        self.txt.configure(state="disabled")
        # also persist to a file so the log survives / can be inspected without
        # attaching a second Frida session (which would collide with our hook)
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(os.path.join(DATA_DIR, "activity.log"), "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {msg}\n")
        except Exception:
            pass

    def _set_status(self, color, text):
        self.status_dot.itemconfig(self._dot, fill=color)
        self.status_lbl.configure(text=text)

    def _poll(self):
        while not self.ui_queue.empty():
            m = self.ui_queue.get()
            k = m.get("kind")
            if k == "log":
                self._log(m["msg"], m.get("level", "info"))
            elif k == "status":
                self._set_status(m["color"], m["text"])
            elif k == "busy":
                self._set_busy(m["on"])
            elif k == "stats":
                d = m["data"]
                if "followers" in d:
                    self.card_vals["followers"].configure(text=str(d["followers"]))
                if "inactive" in d:
                    self.card_vals["inactive"].configure(text=str(d["inactive"]))
                if "mutual" in d:
                    self.card_vals["mutual"].configure(text=str(d["mutual"]))
                if "removed" in d:
                    self.card_vals["removed"].configure(text=str(d["removed"]))
        self.after(80, self._poll)


def run_ui():
    UnfollowerUI().mainloop()


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Icarus Un-follower for Umamusume (reads the friend list, "
                    "removes inactive followers). Run with no command to open the UI.")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("ui", help="open the dashboard UI (default when no command given)")

    a = sub.add_parser("analyze", help="read the follower list, report inactive (no removals)")
    a.add_argument("--days", type=float, default=30,
                   help="inactivity threshold in days; fractions allowed "
                        "(e.g. 0.5 = 12 hours). Default 30")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("run", help="remove inactive followers (dry unless --arm --yes)")
    r.add_argument("--days", type=float, default=30,
                   help="inactivity threshold in days; re-derives the removal set "
                        "from the last scan's stored last-login times (0.5 = 12h)")
    r.add_argument("--max", type=int, default=0, help="max removals this run (0 = all)")
    r.add_argument("--delay", type=float, default=3.0, help="seconds between removals (default 3)")
    r.add_argument("--arm", action="store_true", help="actually send (otherwise dry run)")
    r.add_argument("--yes", action="store_true", help="confirm you want to remove (with --arm)")
    r.add_argument("--include-mutual", action="store_true",
                   help="also remove mutual followers (default: skip them)")
    r.set_defaults(func=cmd_run)

    args = ap.parse_args()
    if args.cmd in (None, "ui"):
        run_ui()
        return
    try:
        args.func(args)
    except frida.ProcessNotFoundError:
        print(f"[error] {PROCESS_NAME} is not running. Start Umamusume first.")
        sys.exit(1)


if __name__ == "__main__":
    main()
