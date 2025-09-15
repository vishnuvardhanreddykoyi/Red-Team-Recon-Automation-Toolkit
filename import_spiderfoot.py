import sqlite3
import json
import time
import hashlib
import uuid
from collections import defaultdict


DB_PATH = r"C:\Users\Vishnu Vardhan Reddy\.spiderfoot\spiderfoot.db"


with open(r"C:\npncyber\clients\reports\normalized_events.json", "r") as f:
    scan_json = json.load(f)

scan_events = scan_json.get("events", [])


events_by_target = defaultdict(list)
for event in scan_events:
    target = event.get("target", "unknown")
    events_by_target[target].append(event)


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()


for target, events in events_by_target.items():
    
    scan_guid = str(uuid.uuid4())
    scan_name = f"Custom Scan for {target} - {time.strftime('%Y-%m-%d %H:%M:%S')}"
    seed_target = target
    created_time = int(time.time())
    started_time = created_time + 5  
    ended_time = started_time + len(events) * 2  
    status = "FINISHED"

    cursor.execute("""
    INSERT INTO tbl_scan_instance (guid, name, seed_target, created, started, ended, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (scan_guid, scan_name, seed_target, created_time, started_time, ended_time, status))

    
    log_generated = started_time
    cursor.execute("""
    INSERT INTO tbl_scan_log (scan_instance_id, generated, component, type, message)
    VALUES (?, ?, ?, ?, ?)
    """, (scan_guid, log_generated, "sfp_custom", "INFO", f"Starting custom import for {target}"))

    log_generated += 5
    cursor.execute("""
    INSERT INTO tbl_scan_log (scan_instance_id, generated, component, type, message)
    VALUES (?, ?, ?, ?, ?)
    """, (scan_guid, log_generated, "sfp_custom", "INFO", f"Processing {len(events)} events"))

    
    root_type = "ROOT"
    root_data = seed_target
    root_hash = hashlib.md5((root_type + ":" + root_data.lower()).encode()).hexdigest()
    root_generated = started_time
    root_confidence = 100
    root_visibility = 100
    root_risk = 0
    root_module = ""
    root_false_positive = 0
    root_source_event_hash = ""

    cursor.execute("""
    INSERT INTO tbl_scan_results
    (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_guid, root_hash, root_type, root_generated, root_confidence, root_visibility, root_risk, root_module, root_data, root_false_positive, root_source_event_hash))

    
    generated_time = started_time + 1
    for event in events:
        original_type = event.get("type", "CUSTOM")
        value = event.get("value")
        module = "sfp_custom" 
        
        confidence = 100
        visibility = 100
        risk = 0
        false_positive = 0
        
        if original_type == "BUCKETS":
            event_type = "RAW_RIR_DATA"
            data_str = value.get("message", json.dumps(value))
            hash_value = hashlib.md5((event_type + ":" + data_str.lower()).encode()).hexdigest()
            cursor.execute("""
            INSERT INTO tbl_scan_results
            (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_guid, hash_value, event_type, generated_time, confidence, visibility, risk, module, data_str, false_positive, root_hash))
            generated_time += 1
        
        elif original_type == "GITHUB":
            event_type = "LINKED_URL_EXTERNAL"
            data_str = value.get("html_url", json.dumps(value))
            hash_value = hashlib.md5((event_type + ":" + data_str.lower()).encode()).hexdigest()
            cursor.execute("""
            INSERT INTO tbl_scan_results
            (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_guid, hash_value, event_type, generated_time, confidence, visibility, risk, module, data_str, false_positive, root_hash))
            generated_time += 1
        
        elif original_type == "RESULTS":
            subdomain = value.get("subdomain")
            ip = value.get("ip")
            if subdomain:
                sub_event_type = "AFFILIATE_INTERNET_NAME"
                sub_data = subdomain
                sub_hash = hashlib.md5((sub_event_type + ":" + sub_data.lower()).encode()).hexdigest()
                cursor.execute("""
                INSERT INTO tbl_scan_results
                (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_guid, sub_hash, sub_event_type, generated_time, confidence, visibility, risk, module, sub_data, false_positive, root_hash))
                generated_time += 1
                source_for_ip = sub_hash
            else:
                source_for_ip = root_hash
            if ip:
                ip_event_type = "AFFILIATE_IPADDR"
                ip_data = ip
                ip_hash = hashlib.md5((ip_event_type + ":" + ip_data.lower()).encode()).hexdigest()
                cursor.execute("""
                INSERT INTO tbl_scan_results
                (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_guid, ip_hash, ip_event_type, generated_time, confidence, visibility, risk, module, ip_data, false_positive, source_for_ip))
                generated_time += 1
        
        elif original_type.startswith("TECHNOLOGIES_"):
            event_type = "SOFTWARE_USED"
            if isinstance(value, list):
                for item in value:
                    data_str = item
                    hash_value = hashlib.md5((event_type + ":" + data_str.lower()).encode()).hexdigest()
                    cursor.execute("""
                    INSERT INTO tbl_scan_results
                    (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (scan_guid, hash_value, event_type, generated_time, confidence, visibility, risk, module, data_str, false_positive, root_hash))
                    generated_time += 1
        
        elif original_type == "REPORT_GOOGLE.COM":
            event_type = "DOMAIN_WHOIS"
            data_str = json.dumps(value, indent=4)
            hash_value = hashlib.md5((event_type + ":" + data_str.lower()).encode()).hexdigest()
            cursor.execute("""
            INSERT INTO tbl_scan_results
            (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_guid, hash_value, event_type, generated_time, confidence, visibility, risk, module, data_str, false_positive, root_hash))
            generated_time += 1
        
        else:
            
            event_type = "RAW_RIR_DATA"
            data_str = json.dumps(value)
            hash_value = hashlib.md5((event_type + ":" + data_str.lower()).encode()).hexdigest()
            cursor.execute("""
            INSERT INTO tbl_scan_results
            (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_guid, hash_value, event_type, generated_time, confidence, visibility, risk, module, data_str, false_positive, root_hash))
            generated_time += 1

    
    log_generated = ended_time
    cursor.execute("""
    INSERT INTO tbl_scan_log (scan_instance_id, generated, component, type, message)
    VALUES (?, ?, ?, ?, ?)
    """, (scan_guid, log_generated, "sfp_custom", "INFO", "Custom import completed"))


conn.commit()
conn.close()

print(f"Inserted data into SpiderFoot database. Created {len(events_by_target)} scan instances for unique targets.")