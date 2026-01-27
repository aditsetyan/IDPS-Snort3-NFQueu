import os

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.conf import settings


@login_required
def index(request):
    return render(request, 'dashboard/index.html')


@login_required
def dashboard_data_api(request):

    import json
    import re
    import datetime
    from collections import Counter

    # ======================================================
    # SETUP TANGGAL
    # ======================================================
    now = datetime.datetime.now()
    today_date = now.date()
    week_start_date = today_date - datetime.timedelta(days=6)  # 7 hari terakhir

    # Helper konversi timestamp JSON
    def parse_dt(ts):
        try:
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            return None

    # ======================================================
    # 1. Temukan file log Snort
    # ======================================================
    snort_log_path = None
    dashboard_candidates = []

    preferred_fast = getattr(settings, "SNORT_DASHBOARD_LOG_PATH", "")
    if preferred_fast:
        dashboard_candidates.append(preferred_fast)

    configured_fast = getattr(settings, "SNORT_LOG_FAST_PATH", "")
    if configured_fast and configured_fast not in dashboard_candidates:
        dashboard_candidates.append(configured_fast)

    configured_generic = getattr(settings, "SNORT_LOG_PATH", "")
    if configured_generic and configured_generic not in dashboard_candidates:
        dashboard_candidates.append(configured_generic)

    dashboard_candidates.extend(
        ["/var/log/snort/alert_fast.txt", "/var/log/snort/alert_json.txt"]
    )

    for candidate in dashboard_candidates:
        if candidate and os.path.isfile(candidate):
            snort_log_path = candidate
            break

    if not snort_log_path and dashboard_candidates:
        snort_log_path = dashboard_candidates[0]

    # ======================================================
    # 2. Hitung TOTAL ALERT (tanpa filter)
    # ======================================================
    try:
        with open(snort_log_path, 'r', encoding="utf-8", errors="ignore") as f:
            total_alerts = sum(1 for _ in f)
    except:
        total_alerts = 0

    # ======================================================
    # 3. Hitung rules Snort
    # ======================================================
    total_rules = 0
    try:
        from snort.views import _list_rule_files
        rule_files = _list_rule_files()

        for item in rule_files:
            count = item.get("rule_count")
            if count is None:
                try:
                    with open(item["path"], "r", encoding="utf-8", errors="ignore") as f:
                        count = sum(
                            1 for ln in f
                            if ln.strip() and not ln.lstrip().startswith("#")
                        )
                except:
                    continue
            total_rules += count or 0
    except:
        pass

    # ======================================================
    # 4. Hitung whitelist & blocklist
    # ======================================================
    def _count_ip_entries(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return sum(
                    1 for ln in f
                    if ln.strip() and not ln.lstrip().startswith("#")
                )
        except:
            return 0

    total_ip_whitelist = _count_ip_entries(
        getattr(settings, "SNORT_IP_WHITELIST_PATH", "")
    )
    total_ip_blocklist = _count_ip_entries(
        getattr(settings, "SNORT_IP_BLOCKLIST_PATH", "")
    )

    # ======================================================
    # 5. ALERT PER JAM — Reset setiap hari (hanya TODAY)
    # ======================================================
    alert_hour_alert = Counter()
    alert_hour_drop = Counter()

    regex_fast = re.compile(r".*\[(ALERT|DROP)\]", re.IGNORECASE)

    def process_hour(dt, act):
        if not dt:
            return
        if dt.date() != today_date:
            return

        hour_key = dt.strftime("%H")
        if act == "alert":
            alert_hour_alert[hour_key] += 1
        elif act == "drop":
            alert_hour_drop[hour_key] += 1

    # ======================================================
    # 6. ALERT PER MINGGU — Reset setiap 7 hari
    # ======================================================
    alert_week_alert = Counter()
    alert_week_drop = Counter()

    weekday_map = {
        0: "Senin", 1: "Selasa", 2: "Rabu",
        3: "Kamis", 4: "Jumat", 5: "Sabtu", 6: "Minggu"
    }

    def process_week(dt, act):
        if not dt:
            return
        if dt.date() < week_start_date:
            return

        wd = weekday_map[dt.weekday()]
        if act == "alert":
            alert_week_alert[wd] += 1
        elif act == "drop":
            alert_week_drop[wd] += 1

    # ======================================================
    # 7. LOOP FILE LOG — JSON & FAST format
    # ======================================================
    try:
        with open(snort_log_path, "r", encoding="utf-8", errors="ignore") as f:

            for line in f:
                line = line.strip()
                if not line:
                    continue

                # JSON Mode
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        ts = obj.get("timestamp") or obj.get("time")
                        act = (obj.get("action") or "").lower()
                        dt = parse_dt(ts)

                        process_hour(dt, act)
                        process_week(dt, act)
                        continue
                    except:
                        pass

                # FAST Mode
                fast_match = re.match(r"(\d+/\d+)-(\d+):(\d+):(\d+)", line)
                action_tag = regex_fast.search(line)

                if fast_match:
                    month, day = map(int, fast_match.group(1).split("/"))
                    hr, mn, sc = map(int, fast_match.groups()[1:4])
                    act = action_tag.group(1).lower() if action_tag else None

                    try:
                        dt = datetime.datetime(now.year, month, day, hr, mn, sc)
                    except:
                        dt = None

                    process_hour(dt, act)
                    process_week(dt, act)

    except Exception as e:
        print("ERROR membaca log:", e)

    # ======================================================
    # LABEL & OUTPUT
    # ======================================================
    hour_labels = [f"{h:02d}.00" for h in range(24)]
    week_labels = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]

    return JsonResponse({
        "total_alerts": total_alerts,
        "total_rules": total_rules,
        "total_ip_whitelist": total_ip_whitelist,
        "total_ip_blocklist": total_ip_blocklist,

        "alert_hour_labels": hour_labels,
        "alert_hour_alert": [alert_hour_alert.get(f"{h:02d}", 0) for h in range(24)],
        "alert_hour_drop": [alert_hour_drop.get(f"{h:02d}", 0) for h in range(24)],

        "alert_week_labels": week_labels,
        "alert_week_alert": [alert_week_alert.get(d, 0) for d in week_labels],
        "alert_week_drop": [alert_week_drop.get(d, 0) for d in week_labels],
    })
