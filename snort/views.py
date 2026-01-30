from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.conf import settings
from django.utils import timezone
from django.contrib import messages
from django.urls import reverse
import json
import os
import re
from datetime import datetime, timezone as dt_timezone

# --- ROLE CHECKER ---

def is_admin_staff(user):
    """Cek apakah user adalah Superuser atau masuk dalam grup 'admin'."""
    return user.is_superuser or user.groups.filter(name='admin').exists()

# --- INTERNAL HELPER FUNCTIONS ---

def _candidate_log_paths():
    candidates = [
        getattr(settings, "SNORT_LOG_JSON_PATH", ""),
        getattr(settings, "SNORT_LOG_PATH", ""),
        getattr(settings, "SNORT_LOG_FAST_PATH", ""),
        "/var/log/snort/alert_json.txt",
        "/var/log/snort/alert_fast.txt",
    ]
    seen = set()
    ordered = []
    for path in candidates:
        if path and path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered

def _iter_existing_files():
    for candidate in _candidate_log_paths():
        for path in _resolve_candidate_files(candidate):
            yield path

def _resolve_candidate_files(candidate):
    if os.path.isdir(candidate):
        try:
            entries = sorted(os.listdir(candidate))
        except (FileNotFoundError, PermissionError):
            return []
        files = [os.path.join(candidate, name) for name in entries if os.path.isfile(os.path.join(candidate, name))]
        try:
            files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        except OSError:
            files.sort(reverse=True)
        return files
    if os.path.exists(candidate):
        return [candidate]
    return []

def _list_all_log_files():
    files = []
    seen = set()
    for candidate in _candidate_log_paths():
        for path in _resolve_candidate_files(candidate):
            if path not in seen:
                seen.add(path)
                files.append(path)
    return files

def _clear_log_files(target_paths=None):
    cleared = 0
    errors = []
    seen = set()
    paths = target_paths if target_paths is not None else _list_all_log_files()
    for path in paths:
        if path in seen: continue
        seen.add(path)
        try:
            with open(path, "w", encoding="utf-8"): pass
            cleared += 1
        except Exception as exc:
            errors.append((path, str(exc)))
    return cleared, errors

def _candidate_rule_dirs():
    candidates = [getattr(settings, "SNORT_RULES_DIR", ""), "/usr/local/etc/rules/"]
    seen = set()
    ordered = [e for e in candidates if e and e not in seen and not seen.add(e)]
    return ordered

def _list_rule_files():
    files = []
    seen = set()
    for directory in _candidate_rule_dirs():
        if not os.path.isdir(directory): continue
        try:
            entries = sorted(os.listdir(directory))
        except: continue
        for name in entries:
            if not name.endswith(".rules"): continue
            path = os.path.join(directory, name)
            if path in seen or not os.path.isfile(path): continue
            seen.add(path)
            try: stats = os.stat(path)
            except: stats = None
            rule_count = None
            if stats and stats.st_size <= 5 * 1024 * 1024:
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as h:
                        rule_count = sum(1 for ln in h if ln.strip() and not ln.lstrip().startswith("#"))
                except: rule_count = None
            files.append({
                "name": name, "path": path, "directory": directory, "size": stats.st_size if stats else None,
                "modified": datetime.fromtimestamp(stats.st_mtime, timezone.get_current_timezone()) if stats else None,
                "rule_count": rule_count,
            })
    files.sort(key=lambda item: item["name"].lower())
    return files

def _read_rule_file(file_path, search_term=None, max_lines=5000):
    if not file_path: return [], None, False
    search_lower = search_term.lower() if search_term else None
    rows, error, truncated = [], None, False
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for idx, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\n")
                if search_lower and search_lower not in line.lower(): continue
                rows.append({"number": idx, "content": line, "is_comment": line.lstrip().startswith("#")})
                if len(rows) >= max_lines:
                    truncated = True
                    break
    except Exception as exc: error = str(exc)
    return rows, error, truncated

def _extract_filter_params(params):
    filters = {k: params.get(k, "").strip() for k in ["search", "signature", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "time_from", "time_to"]}
    parsed = {"time_from": None, "time_to": None, "src_port": int(filters["src_port"]) if filters["src_port"].isdigit() else None, "dst_port": int(filters["dst_port"]) if filters["dst_port"].isdigit() else None}
    return filters, parsed

def _apply_filters(alerts, filters, parsed):
    results = []
    search = filters["search"].lower()
    for alert in alerts:
        if filters["action"] and filters["action"] != alert.get("action"): continue
        if search:
            haystack = f"{alert.get('timestamp')} {alert.get('signature')} {alert.get('src_ip')} {alert.get('dst_ip')}".lower()
            if search not in haystack: continue
        results.append(alert)
    return results

def _normalize_timestamp(value):
    if not value: return None, "N/A"
    try:
        # Gunakan timezone aware agar tidak error saat sorting
        dt = timezone.now() 
        return dt, dt.strftime("%Y-%m-%d %H:%M:%S")
    except: return None, value

def _parse_json_line(line):
    try: 
        raw = json.loads(line)
        dt, ts_display = _normalize_timestamp(raw.get("timestamp"))
        return {
            "timestamp": ts_display, "signature": raw.get("msg", "N/A") or raw.get("message", "N/A"),
            "src_ip": raw.get("src_ip", "N/A"), "src_port": raw.get("src_port", "N/A"),
            "dst_ip": raw.get("dest_ip", "N/A"), "dst_port": raw.get("dest_port", "N/A"),
            "protocol": raw.get("proto", "N/A"), "priority": raw.get("priority", "N/A"),
            "action": "drop" if "drop" in str(raw.get("action")).lower() else "alert",
            "sort_key": dt,
        }
    except: return None

def _parse_fast_line(line):
    if "[**]" not in line: return None
    try:
        dt, ts_display = _normalize_timestamp(line.split(" ")[0])
        return {
            "timestamp": ts_display, "signature": "Fast Alert", "src_ip": "N/A", "src_port": "N/A",
            "dst_ip": "N/A", "dst_port": "N/A", "protocol": "N/A", "priority": "N/A",
            "action": "alert", "sort_key": dt,
        }
    except: return None

# --- VIEW FUNCTIONS ---

@login_required
def logs(request):
    if request.method == "POST":
        if not is_admin_staff(request.user):
            messages.error(request, "Akses Ditolak: Anda tidak memiliki izin mengosongkan log.")
            return redirect('snort:logs')
        if request.POST.get("action") == "clear":
            cleared, errors = _clear_log_files()
            if cleared: messages.success(request, f"{cleared} log berhasil dikosongkan.")
        return redirect('snort:logs')

    alerts = []
    source_files = []
    try:
        for path in _iter_existing_files():
            with open(path, "r") as handle:
                for ln in handle:
                    parsed = _parse_json_line(ln) or _parse_fast_line(ln)
                    if parsed: alerts.append(parsed)
            if alerts: source_files.append(path); break
    except: pass

    alerts.sort(key=lambda x: x.get("sort_key") or datetime.min.replace(tzinfo=dt_timezone.utc), reverse=True)
    filters, parsed_filters = _extract_filter_params(request.GET)
    alerts = _apply_filters(alerts, filters, parsed_filters)

    paginator = Paginator(alerts, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj, 'total_alerts': len(alerts), 'filters': filters,
        'active_log_files': [{"name": os.path.basename(p), "path": p} for p in source_files],
        'is_admin': is_admin_staff(request.user)
    }
    return render(request, 'snort/logs.html', context)

@login_required
def rules(request):
    search_term = request.GET.get("search", "").strip()
    requested_file = request.GET.get("file", "").strip()
    rule_files = _list_rule_files()
    selected_file = next((f for f in rule_files if requested_file in (f["name"], f["path"])), rule_files[0] if rule_files else None)
    rules_preview, read_error, truncated = _read_rule_file(selected_file["path"], search_term=search_term) if selected_file else ([], None, False)

    context = {
        "rule_files": rule_files, "selected_file": selected_file, "rules_preview": rules_preview,
        "search_term": search_term, "read_error": read_error, "truncated": truncated,
        "total_rule_files": len(rule_files), "total_rules_all": sum(f.get("rule_count") or 0 for f in rule_files),
        'is_admin': is_admin_staff(request.user)
    }
    return render(request, "snort/rules.html", context)

@login_required
def ip_whitelist(request):
    path = getattr(settings, "SNORT_IP_WHITELIST_PATH", "")
    entries = []
    if os.path.isfile(path):
        with open(path, "r") as f:
            entries = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    return render(request, "snort/whitelist.html", {"entries": entries, "total": len(entries), 'is_admin': is_admin_staff(request.user)})

@login_required
def ip_blocklist(request):
    path = getattr(settings, "SNORT_IP_BLOCKLIST_PATH", "")
    entries = []
    if os.path.isfile(path):
        with open(path, "r") as f:
            entries = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    return render(request, "snort/blocklist.html", {"entries": entries, "total": len(entries), 'is_admin': is_admin_staff(request.user)})