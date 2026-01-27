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
from django.contrib.auth.decorators import user_passes_test

def is_admin(user):
    return user.is_superuser or user.groups.filter(name='admin').exists()

def _candidate_log_paths():
    candidates = [
        getattr(settings, "SNORT_LOG_JSON_PATH", ""),
        getattr(settings, "SNORT_LOG_PATH", ""),
        getattr(settings, "SNORT_LOG_FAST_PATH", ""),
        "/var/log/snort/alert_json.txt",
        "/var/log/snort/alert_fast.txt",
    ]
    # Preserve order while removing empty entries and duplicates
    seen = set()
    ordered = []
    for path in candidates:
        if not path:
            continue
        if path in seen:
            continue
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
        files = [
            os.path.join(candidate, name)
            for name in entries
            if os.path.isfile(os.path.join(candidate, name))
        ]
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
            if path in seen:
                continue
            seen.add(path)
            files.append(path)
    return files


def _clear_log_files(target_paths=None):
    cleared = 0
    errors = []
    seen = set()

    paths = target_paths if target_paths is not None else _list_all_log_files()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        try:
            with open(path, "w", encoding="utf-8"):
                pass
            cleared += 1
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            errors.append((path, str(exc)))
        except OSError as exc:
            errors.append((path, str(exc)))

    return cleared, errors


def _candidate_rule_dirs():
    candidates = [
        getattr(settings, "SNORT_RULES_DIR", ""),
        "/usr/local/etc/rules/",
    ]
    seen = set()
    ordered = []
    for entry in candidates:
        if not entry or entry in seen:
            continue
        seen.add(entry)
        ordered.append(entry)
    return ordered


def _list_rule_files():
    files = []
    seen = set()
    for directory in _candidate_rule_dirs():
        if not os.path.isdir(directory):
            continue
        try:
            entries = sorted(os.listdir(directory))
        except (FileNotFoundError, PermissionError):
            continue
        for name in entries:
            if not name.endswith(".rules"):
                continue
            path = os.path.join(directory, name)
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            try:
                stats = os.stat(path)
            except (FileNotFoundError, PermissionError, OSError):
                stats = None

            rule_count = None
            if stats and stats.st_size <= 5 * 1024 * 1024:  # skip huge files for quick summary
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                        rule_count = sum(
                            1
                            for line in handle
                            if line.strip() and not line.lstrip().startswith("#")
                        )
                except (OSError, UnicodeDecodeError):
                    rule_count = None

            files.append(
                {
                    "name": name,
                    "path": path,
                    "directory": directory,
                    "size": stats.st_size if stats else None,
                    "modified": datetime.fromtimestamp(stats.st_mtime, timezone.get_current_timezone())
                    if stats
                    else None,
                    "rule_count": rule_count,
                }
            )
    files.sort(key=lambda item: item["name"].lower())
    return files


def _read_rule_file(file_path, search_term=None, max_lines=5000):
    if not file_path:
        return [], None, False

    search_lower = search_term.lower() if search_term else None
    rows = []
    error = None
    truncated = False

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for idx, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\n")
                if search_lower and search_lower not in line.lower():
                    continue
                rows.append(
                    {
                        "number": idx,
                        "content": line,
                        "is_comment": line.lstrip().startswith("#"),
                    }
                )
                if len(rows) >= max_lines:
                    truncated = True
                    break
    except FileNotFoundError:
        error = "File tidak ditemukan."
    except PermissionError:
        error = "Tidak memiliki izin membaca file aturan."
    except OSError as exc:
        error = f"Gagal membaca file: {exc}"

    return rows, error, truncated



def _extract_filter_params(params):
    filters = {
        "search": params.get("search", "").strip(),
        "signature": params.get("signature", "").strip(),
        "src_ip": params.get("src_ip", "").strip(),
        "dst_ip": params.get("dst_ip", "").strip(),
        "src_port": params.get("src_port", "").strip(),
        "dst_port": params.get("dst_port", "").strip(),
        "protocol": params.get("protocol", "").strip(),
        "action": params.get("action", "").strip().lower(),
        "time_from": params.get("time_from", "").strip(),
        "time_to": params.get("time_to", "").strip(),
    }

    # Backwards compatibility with legacy single ip/port parameters
    legacy_ip = params.get("ip", "").strip()
    if legacy_ip and not filters["src_ip"] and not filters["dst_ip"]:
        filters["src_ip"] = legacy_ip

    legacy_port = params.get("port", "").strip()
    if legacy_port and not filters["src_port"] and not filters["dst_port"]:
        filters["src_port"] = legacy_port

    legacy_priority = params.get("priority", "").strip()
    if not filters["action"] and legacy_priority:
        filters["action"] = "drop" if legacy_priority == "1" else "alert"

    def _parse_port(value: str):
        try:
            return int(value) if value else None
        except ValueError:
            return None

    parsed = {
        "time_from": None,
        "time_to": None,
        "src_port": _parse_port(filters["src_port"]),
        "dst_port": _parse_port(filters["dst_port"]),
    }

    return filters, parsed


def _apply_filters(alerts, filters, parsed):
    search_term = filters["search"].lower()
    signature_term = filters["signature"].lower()
    src_ip_term = filters["src_ip"].lower()
    dst_ip_term = filters["dst_ip"].lower()
    protocol_term = filters["protocol"].lower()
    action_term = filters["action"]
    start_time = parsed["time_from"]
    end_time = parsed["time_to"]
    src_port_value = parsed["src_port"]
    dst_port_value = parsed["dst_port"]

    results = []

    for alert in alerts:
        sort_key = alert.get("sort_key")
        if start_time and (sort_key is None or sort_key < start_time):
            continue
        if end_time and (sort_key is None or sort_key > end_time):
            continue

        timestamp = str(alert.get("timestamp", ""))
        signature = str(alert.get("signature", ""))
        src_ip = str(alert.get("src_ip", ""))
        dst_ip = str(alert.get("dst_ip", ""))
        src_port = str(alert.get("src_port", ""))
        dst_port = str(alert.get("dst_port", ""))
        protocol = str(alert.get("protocol", ""))
        priority = str(alert.get("priority", ""))
        action_value = str(alert.get("action", "")).lower() or "alert"

        if search_term:
            haystack = " ".join(
                [timestamp, signature, src_ip, dst_ip, src_port, dst_port, protocol, priority]
            ).lower()
            if search_term not in haystack:
                continue

        if signature_term and signature_term not in signature.lower():
            continue

        if src_ip_term and src_ip_term not in src_ip.lower():
            continue

        if dst_ip_term and dst_ip_term not in dst_ip.lower():
            continue

        if src_port_value is not None and src_port != str(src_port_value):
            continue

        if dst_port_value is not None and dst_port != str(dst_port_value):
            continue

        if protocol_term and protocol_term not in protocol.lower():
            continue

        if action_term and action_term != action_value:
            continue

        results.append(alert)

    return results


def _normalize_timestamp(value):
    if value in (None, ""):
        return None, "N/A"

    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, timezone.get_current_timezone())
        return dt, timezone.localtime(dt).strftime("%Y-%m-%d %H:%M:%S")

    tz = timezone.get_current_timezone()
    now = timezone.now()
    formats = [
        ("%Y-%m-%dT%H:%M:%S.%f%z", False),
        ("%Y-%m-%dT%H:%M:%S%z", False),
        ("%Y-%m-%dT%H:%M:%S.%fZ", False),
        ("%Y-%m-%dT%H:%M:%SZ", False),
        ("%Y-%m-%d %H:%M:%S.%f%z", False),
        ("%Y-%m-%d %H:%M:%S%z", False),
        ("%Y-%m-%dT%H:%M:%S.%f", True),
        ("%Y-%m-%dT%H:%M:%S", True),
        ("%Y-%m-%d %H:%M:%S.%f", True),
        ("%Y-%m-%d %H:%M:%S", True),
        ("%m/%d-%H:%M:%S.%f", "no_year"),
        ("%m/%d-%H:%M:%S", "no_year"),
    ]

    for fmt, behaviour in formats:
        try:
            dt = datetime.strptime(value, fmt)
        except ValueError:
            continue

        if behaviour == "no_year":
            try:
                dt = dt.replace(year=now.year)
            except ValueError:
                dt = dt.replace(year=now.year - 1)
        if behaviour:
            dt = timezone.make_aware(dt, tz)
        elif timezone.is_naive(dt):
            dt = timezone.make_aware(dt, tz)

        return dt, timezone.localtime(dt).strftime("%Y-%m-%d %H:%M:%S")

    return None, value


def _split_ip_port(value):
    if not value:
        return None, None
    value = str(value).strip()

    if value.startswith("[") and "]" in value:
        ip_part, _, remainder = value[1:].partition("]")
        port = remainder.lstrip(":") if remainder else None
        return ip_part or None, port or None

    if " " in value:
        value = value.split(" ", 1)[0]

    if ":" in value:
        ip, port = value.rsplit(":", 1)
        if port.isdigit():
            return ip or None, port or None
        return value, None

    return value, None


def _get_from_dict(data, key_paths):
    for path in key_paths:
        current = data
        missing = False
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                missing = True
                break
        if not missing and current not in (None, ""):
            return current
    return None


def _extract_ip_port(data, key_prefix):
    direct_value = _get_from_dict(
        data,
        [
            (f"{key_prefix}_addr",),
            (f"{key_prefix}_ip",),
            (key_prefix,),
            (key_prefix, "ip"),
            (key_prefix, "addr"),
            (key_prefix, "address"),
            (key_prefix, "address", "ip"),
            (key_prefix, "address", "addr"),
        ],
    )

    ip = None
    port = None

    if isinstance(direct_value, dict):
        ip = _get_from_dict(
            direct_value,
            [("ip",), ("addr",), ("address",)],
        )
        port = _get_from_dict(
            direct_value,
            [("port",), ("sport",), ("dport",), ("source_port",), ("dest_port",)],
        )
    elif direct_value:
        ip, port = _split_ip_port(direct_value)

    if not ip:
        ip = _get_from_dict(
            data,
            [
                (f"{key_prefix}_addr",),
                (f"{key_prefix}_ip",),
                (f"{key_prefix}_address",),
            ],
        )
    if not port:
        port = _get_from_dict(
            data,
            [
                (f"{key_prefix}_port",),
                (f"{key_prefix}_sport",),
                (f"{key_prefix}_dport",),
            ],
        )
    return ip, port


def _parse_json_line(line):
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    timestamp = _get_from_dict(raw, [("timestamp",), ("time",), ("event", "timestamp")])
    dt, ts_display = _normalize_timestamp(timestamp)

    alert_block = raw if isinstance(raw, dict) else {}
    inner_alert = alert_block.get("alert") if isinstance(alert_block, dict) else {}
    if not isinstance(inner_alert, dict):
        inner_alert = {}

    action_raw = (
        _get_from_dict(inner_alert, [("action",)])
        or _get_from_dict(alert_block, [("action",), ("event_type",)])
    )
    action = str(action_raw).strip().lower() if action_raw not in (None, "") else "alert"
    if action in {"drop", "dropped", "block", "blocked"}:
        action = "drop"
    else:
        action = "alert"

    signature = (
        _get_from_dict(raw, [("msg",), ("message",)])
        or _get_from_dict(inner_alert, [("signature",), ("msg",)])
        or "N/A"
    )
    signature = str(signature).strip()

    priority_value = (
        _get_from_dict(raw, [("priority",), ("severity",)])
        or _get_from_dict(inner_alert, [("priority",), ("severity",)])
    )
    priority = (
        str(priority_value)
        if priority_value not in (None, "")
        else "N/A"
    )

    protocol_value = (
        _get_from_dict(raw, [("proto",), ("protocol",), ("ip_proto",)])
        or _get_from_dict(inner_alert, [("proto",), ("protocol",)])
    )
    protocol = str(protocol_value) if protocol_value not in (None, "") else "N/A"

    src_ip, src_port = _extract_ip_port(raw, "src")
    if not src_ip:
        src_ip = _get_from_dict(inner_alert, [("src_ip",), ("src_addr",)])
    if not src_port:
        src_port = _get_from_dict(inner_alert, [("src_port",), ("sport",)])

    dst_ip, dst_port = _extract_ip_port(raw, "dest")
    if not dst_ip:
        dst_ip = _get_from_dict(inner_alert, [("dest_ip",), ("dest_addr",)])
    if not dst_port:
        dst_port = _get_from_dict(inner_alert, [("dest_port",), ("dport",)])

    return {
        "timestamp": ts_display,
        "signature": signature,
        "src_ip": src_ip or "N/A",
        "src_port": src_port if src_port not in (None, "") else "N/A",
        "dst_ip": dst_ip or "N/A",
        "dst_port": dst_port if dst_port not in (None, "") else "N/A",
        "protocol": protocol,
        "priority": priority,
        "action": action,
        "sort_key": dt,
    }


def _parse_fast_line(line):
    action = "alert"
    action_match = re.search(r"\[(alert|drop|log|pass)\]", line, re.IGNORECASE)
    if action_match:
        value = action_match.group(1).lower()
        action = "drop" if value in {"drop", "dropped", "block"} else "alert"

    parts = line.split("[**]")
    if len(parts) < 3:
        return None

    timestamp_segment = parts[0]
    if "[" in timestamp_segment:
        timestamp_segment = timestamp_segment.split("[")[0]
    timestamp_raw = timestamp_segment.strip()
    dt, ts_display = _normalize_timestamp(timestamp_raw)

    sig_section = parts[1].strip()
    if sig_section.startswith("["):
        closing = sig_section.find("]")
        if closing != -1:
            sig_section = sig_section[closing + 1 :].strip()
    signature = sig_section or "N/A"

    tail = parts[2].strip()

    classification_match = re.search(r"\[Classification:\s*([^\]]+)\]", tail)
    if classification_match:
        tail = tail.replace(classification_match.group(0), "").strip()

    priority_match = re.search(r"\[Priority:\s*([^\]]+)\]", tail)
    if priority_match:
        priority = priority_match.group(1)
        tail = tail.replace(priority_match.group(0), "").strip()
    else:
        priority = "N/A"

    protocol_match = re.search(r"\{([^}]+)\}", tail)
    if protocol_match:
        protocol = protocol_match.group(1)
        tail = tail.split("}", 1)[1].strip()
    else:
        protocol = "N/A"

    if "->" in tail:
        src_part, dst_part = [segment.strip() for segment in tail.split("->", 1)]
    else:
        src_part, dst_part = tail.strip(), ""

    src_ip, src_port = _split_ip_port(src_part)
    dst_ip, dst_port = _split_ip_port(dst_part)

    return {
        "timestamp": ts_display,
        "signature": signature,
        "src_ip": src_ip or "N/A",
        "src_port": src_port or "N/A",
        "dst_ip": dst_ip or "N/A",
        "dst_port": dst_port or "N/A",
        "protocol": protocol,
        "priority": priority,
        "action": action,
        "sort_key": dt,
    }

@login_required
@user_passes_test(is_admin, login_url='/')
def logs(request):
    if request.method == "POST":
        if request.POST.get("action") == "clear":
            cleared, errors = _clear_log_files()

            if cleared:
                messages.success(request, f"{cleared} file log Snort berhasil dikosongkan.")
            elif not errors:
                messages.info(request, "Tidak ditemukan file log Snort untuk dihapus.")

            if errors:
                failed_names = ", ".join(os.path.basename(path) for path, _ in errors[:3])
                messages.error(
                    request,
                    f"Gagal menghapus sebagian log (contoh: {failed_names}). "
                    "Periksa hak akses file log Snort.",
                )

        redirect_url = reverse("snort:logs")
        if request.GET:
            redirect_url = f"{redirect_url}?{request.GET.urlencode()}"
        return redirect(redirect_url)

    alerts = []
    source_files = []

    try:
        for path in _iter_existing_files():
            parsed_any = False
            with open(path, "r") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    parsed = _parse_json_line(line) or _parse_fast_line(line)
                    if parsed:
                        alerts.append(parsed)
                        parsed_any = True
            if parsed_any:
                source_files.append(path)
            if alerts:
                break
    except FileNotFoundError:
        alerts = []
    except Exception as e:
        print(f"Error reading Snort logs: {e}")
        alerts = []

    # Sort by timestamp (newest first)
    alerts.sort(
        key=lambda x: x.get("sort_key") or datetime.min.replace(tzinfo=dt_timezone.utc),
        reverse=True,
    )

    filters, parsed_filters = _extract_filter_params(request.GET)
    alerts = _apply_filters(alerts, filters, parsed_filters)

    # Pagination
    paginator = Paginator(alerts, 50)  # 50 items per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'total_alerts': len(alerts),
        'filters': filters,
        'active_log_files': [
            {
                "name": os.path.basename(path) or path,
                "path": path,
            }
            for path in source_files
        ],
    }
    
    return render(request, 'snort/logs.html', context)


@login_required
@user_passes_test(is_admin, login_url='/')
def rules(request):
    search_term = request.GET.get("search", "").strip()
    requested_file = request.GET.get("file", "").strip()
    file_search_raw = request.GET.get("file_search", "").strip()
    file_search = file_search_raw.lower()

    rule_files = _list_rule_files()
    if file_search:
        rule_files = [
            item for item in rule_files if file_search in item["name"].lower()
        ]

    selected_file = None
    if requested_file:
        for item in rule_files:
            if requested_file in (item["name"], item["path"]):
                selected_file = item
                break
    if not selected_file and rule_files:
        selected_file = rule_files[0]

    total_rule_files = len(rule_files)
    total_rules_all = sum(
        item.get("rule_count") or 0 for item in rule_files if item.get("rule_count") is not None
    )
    any_unknown_rules = any(item.get("rule_count") is None for item in rule_files)

    rules_preview = []
    read_error = None
    truncated = False
    if selected_file:
        rules_preview, read_error, truncated = _read_rule_file(
            selected_file["path"],
            search_term=search_term,
            max_lines=800,
        )

    context = {
        "rule_files": rule_files,
        "selected_file": selected_file,
        "rules_preview": rules_preview,
        "search_term": search_term,
        "file_search": file_search_raw,
        "read_error": read_error,
        "truncated": truncated,
        "total_rule_files": total_rule_files,
        "total_rules_all": total_rules_all,
        "any_unknown_rules": any_unknown_rules,
        "selected_rule_count": selected_file.get("rule_count") if selected_file else None,
    }

    return render(request, "snort/rules.html", context)

# =========================================================
#   IP WHITELIST PAGE
# =========================================================
@login_required
@user_passes_test(is_admin, login_url='/')
def ip_whitelist(request):
    """Menampilkan daftar IP whitelist."""
    path = getattr(settings, "SNORT_IP_WHITELIST_PATH", "")

    entries = []
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                entries = [
                    ln.strip()
                    for ln in f
                    if ln.strip() and not ln.lstrip().startswith("#")
                ]
        except:
            entries = []

    context = {
        "entries": entries,
        "file_path": path,
        "total": len(entries),
    }
    return render(request, "snort/whitelist.html", context)


# =========================================================
#   IP BLOCKLIST PAGE
# =========================================================
@login_required
@user_passes_test(is_admin, login_url='/')
def ip_blocklist(request):
    """Menampilkan daftar IP blocklist."""
    path = getattr(settings, "SNORT_IP_BLOCKLIST_PATH", "")

    entries = []
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                entries = [
                    ln.strip()
                    for ln in f
                    if ln.strip() and not ln.lstrip().startswith("#")
                ]
        except:
            entries = []

    context = {
        "entries": entries,
        "file_path": path,
        "total": len(entries),
    }
    return render(request, "snort/blocklist.html", context)
