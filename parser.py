# import re
# APACHE_PATTERN=re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)')
# def parse_log_line(line):
#     line=line.rstrip("\n")
#     m=APACHE_PATTERN.search(line)
#     if m:
#         return {"time":m.group("time"),"ip":m.group("ip"),"request":m.group("request"),"status":m.group("status"),"raw":line}
#     ipm=re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b',line)
#     return {"time":"-","ip":ipm.group(0) if ipm else "N/A","request":line[:500],"status":"-","raw":line} if line.strip() else None
# def parse_log_file(path,limit=10000):
#     rows=[]
#     with open(path,"r",encoding="utf-8",errors="replace") as f:
#         for i,line in enumerate(f):
#             if i>=limit: break
#             r=parse_log_line(line)
#             if r: rows.append(r)
#     return rows



import re
import csv

APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
    r'\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
)


def parse_log_line(line):
    line = line.rstrip("\n")
    m = APACHE_PATTERN.search(line)

    if m:
        return {
            "time": m.group("time"),
            "ip": m.group("ip"),
            "request": m.group("request"),
            "status": m.group("status"),
            "raw": line
        }

    ipm = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)

    return {
        "time": "-",
        "ip": ipm.group(0) if ipm else "N/A",
        "request": line[:500],
        "status": "-",
        "raw": line
    } if line.strip() else None


def parse_log_file(path, limit=10000):
    rows = []

    # Detect and parse CSV files separately.
    if path.lower().endswith(".csv"):
        with open(path, "r", encoding="utf-8-sig",
                  errors="replace", newline="") as f:
            sample = f.read(4096)
            f.seek(0)

            try:
                dialect = csv.Sniffer().sniff(sample)
            except csv.Error:
                dialect = csv.excel

            reader = csv.DictReader(f, dialect=dialect)

            if reader.fieldnames:
                headers = {
                    name.strip().lower(): name
                    for name in reader.fieldnames
                    if name
                }

                # Handle structured log CSV files with recognizable columns.
                ip_col = headers.get("ip") or headers.get("source_ip")
                time_col = (
                    headers.get("time")
                    or headers.get("timestamp")
                    or headers.get("date")
                )
                request_col = (
                    headers.get("request")
                    or headers.get("uri")
                    or headers.get("url")
                )
                status_col = headers.get("status") or headers.get("status_code")

                if ip_col or request_col:
                    for i, item in enumerate(reader):
                        if i >= limit:
                            break

                        ip = (item.get(ip_col) or "").strip() if ip_col else ""
                        request = (
                            (item.get(request_col) or "").strip()
                            if request_col else ""
                        )
                        time_value = (
                            (item.get(time_col) or "").strip()
                            if time_col else ""
                        )
                        status = (
                            (item.get(status_col) or "").strip()
                            if status_col else "-"
                        )

                        # Support previously exported alert-report CSV files.
                        if not request:
                            snippet_col = headers.get("snippet")
                            request = (
                                (item.get(snippet_col) or "").strip()
                                if snippet_col else ""
                            )

                        if not request:
                            continue

                        if not ip:
                            ip_match = re.search(
                                r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
                                request
                            )
                            ip = ip_match.group(0) if ip_match else "N/A"

                        rows.append({
                            "time": time_value or "-",
                            "ip": ip,
                            "request": request[:500],
                            "status": status or "-",
                            "raw": str(item)
                        })

                    if rows:
                        return rows

        # If the CSV is not a recognizable structured log, fall back
        # to parsing its lines as ordinary log text.

    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break

            row = parse_log_line(line)
            if row:
                rows.append(row)

    return rows