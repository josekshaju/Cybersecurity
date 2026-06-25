import json
import argparse
import pandas as pd
import ipaddress
from pathlib import Path
import re
import threading
import sys
import time
import os
from collections import defaultdict
#spinner
def spinner_task(message, stop_event):
    spinner = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{message} {spinner[i % len(spinner)]}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
def run_with_spinner(message, func, *args):
    stop_event = threading.Event()
    t = threading.Thread(target=spinner_task, args=(message, stop_event))
    t.start()
    result = func(*args)
    stop_event.set()
    t.join()
    sys.stdout.write(f"\r{message} Done\n")
    return result
def spin(message):
    stop_event = threading.Event()
    t = threading.Thread(target=spinner_task, args=(message, stop_event))
    t.start()
    return stop_event, t
# parser that converts .conf to .json
def parse_config(file_path,out):
    data = {}
    stack = []
    current = data
    def parse_value(key, value):
        value = value.strip()
        quoted = re.findall(r'"([^"]+)"', value)
        if quoted:
            return quoted
        parts = value.strip('"').split()
        if key == "ip" and len(parts) == 2:
            try:
                return [str(ipaddress.IPv4Interface(f"{parts[0]}/{parts[1]}"))]
            except:
                pass
        return parts if len(parts) > 1 else [value.strip('"')]
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("config "):
                key = line.replace("config ", "").replace(" ", "_")
                block = {}
                current[key] = block
                stack.append(current)
                current = block
            elif line.startswith("edit "):
                name = line.split('"')[1] if '"' in line else line.split()[1]
                block = {}
                current[name] = block
                stack.append(current)
                current = block
            elif line.startswith("set "):
                parts = line.split(maxsplit=2)
                if len(parts) == 3:
                    current[parts[1]] = parse_value(parts[1], parts[2])
            elif line in ["next", "end"]:
                if stack:
                    current = stack.pop()
    path=os.path.join(out,"config.json")
    with open(path,"w") as file:
        json.dump(data, file, indent=4)
    return data
def get_val(d, key):
    val = d.get(key, [])
    return str(val[0]).strip() if val else ""
def get_multi(d, key):
    return [str(v).strip() for v in d.get(key, [])]
def normalize_set(values):
    if not values:
        return set()
    if "all" in values:
        return {"all"}
    return set(values)
def get_section(data, *keys):
    for k in keys:
        if k in data:
            return data[k]
    return {}
#classify interface
def norm(x):
    return str(x).strip()
def get_interface_ip(name, data):
    if name in data.get("system_interface", {}):
        return get_val(data["system_interface"][name], "ip")
    return ""
def is_private_ip(ip_value):
    try:
        if not ip_value:
            return False
        ip_value = str(ip_value).strip()
        if " " in ip_value:
            ip = ip_value.split()[0]
        elif "/" in ip_value:
            ip = ip_value.split("/")[0]
        else:
            ip = ip_value
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def classify_interface(name, details, vpn_phase1, data):
    name_l = name.lower()
    if "dmz" in name_l:
        return "DMZ"
    if "wan" in name_l:
        return "EXTERNAL"
    if get_val(details, "type") == "vlan":
        return "INTERNAL"
    if "ssl" in name_l or name in vpn_phase1:
        return "INTERNAL"
    ip = get_interface_ip(name, data)
    if is_private_ip(ip):
        return "INTERNAL"
    return "EXTERNAL"
#Export services
def export_firewall_services(data, output_path):
    rows = []
    services = data.get("firewall_service_custom", {})
    for service_name, service_data in services.items():
        row = {"service_name": service_name}
        for key, value in service_data.items():
            if isinstance(value, list):
                row[key] = ",".join(map(str, value))
            else:
                row[key] = value
        rows.append(row)
    df = pd.DataFrame(rows)
    df.fillna("", inplace=True)
    df.to_csv(output_path/ "services.csv", index=False)
#export srevice groups
def export_service_groups(data, out):
    rows = []
    svc_groups = {}
    svc_groups.update(data.get("firewall_service_group", {}))
    svc_groups.update(data.get("firewall_service_group_custom", {}))
    svc_groups.update(data.get("firewall_service_grp", {}))
    for group_name, details in svc_groups.items():
        members = details.get("member", [])
        members_str = ", ".join([str(m).strip() for m in members])
        rows.append({
            "service_group": group_name,
            "members": members_str
        })
    df = pd.DataFrame(rows)
    df.fillna("", inplace=True)
    df.to_csv(out / "service_groups.csv", index=False)
#Export any any policies with action accept
def export_any_any_accept_policy(data, out):
    rows = []
    for pid, details in data.get("firewall_policy", {}).items():
        status = get_val(details, "status")
        if status != "enable":
            continue
        svc = set(get_multi(details, "srcintf"))
        dst = set(get_multi(details, "dstintf"))
        action= set(get_multi(details, "action"))
        src_norm = {s.lower() for s in svc}
        dst_norm = {d.lower() for d in dst}
        act_norm={a.lower() for a in action}
        if "any" in src_norm and "any" in dst_norm and "accept" in act_norm:
            rows.append({
               "Policy ID": pid,
                "UUID": get_val(details, "uuid"),
                "Name": get_val(details, "name"),
                "Status": get_val(details, "status"),
                "Src Interface": ", ".join(get_multi(details, "srcintf")),
                "Dst Interface": ", ".join(get_multi(details, "dstintf")),
                "Source Address": ", ".join(get_multi(details, "srcaddr")),
                "Destination Address": ", ".join(get_multi(details, "dstaddr")),
                "Services": ", ".join(get_multi(details, "service")),
                "Schedule": get_val(details, "schedule"),
                "Action": get_val(details, "action"),
                "NAT": get_val(details, "nat"),
                "Logging": get_val(details, "logtraffic"),
                "UTM Status": get_val(details, "utm-status"),
                "Inspection Mode": get_val(details, "inspection-mode"),
                "SSL Profile": get_val(details, "ssl-ssh-profile"),
                "AV Profile": get_val(details, "av-profile"),
                "IPS Sensor": get_val(details, "ips-sensor"),
                "Web Filter": get_val(details, "webfilter-profile"),
                "App Control": get_val(details, "application-list"),
                "User Groups": ", ".join(get_multi(details, "groups")),
                "Users": ", ".join(get_multi(details, "users")),
            })
    df = pd.DataFrame(rows)
    df.to_csv(out/ "any_any_accept.csv", index=False)
#Export any any policy with action deny
def export_any_any_deny_policy(data, out):
    rows = []
    for pid, details in data.get("firewall_policy", {}).items():
        status = get_val(details, "status")
        if status != "enable":
            continue
        svc = set(get_multi(details, "srcintf"))
        dst = set(get_multi(details, "dstintf"))
        action= set(get_multi(details, "action"))
        src_norm = {s.lower() for s in svc}
        dst_norm = {d.lower() for d in dst}
        act_norm={a.lower() for a in action}
        if "any" in src_norm and "any" in dst_norm and "deny" in act_norm:
            rows.append({
               "Policy ID": pid,
                "UUID": get_val(details, "uuid"),
                "Name": get_val(details, "name"),
                "Status": get_val(details, "status"),
                "Src Interface": ", ".join(get_multi(details, "srcintf")),
                "Dst Interface": ", ".join(get_multi(details, "dstintf")),
                "Source Address": ", ".join(get_multi(details, "srcaddr")),
                "Destination Address": ", ".join(get_multi(details, "dstaddr")),
                "Services": ", ".join(get_multi(details, "service")),
                "Schedule": get_val(details, "schedule"),
                "Action": get_val(details, "action"),
                "NAT": get_val(details, "nat"),
                "Logging": get_val(details, "logtraffic"),
                "UTM Status": get_val(details, "utm-status"),
                "Inspection Mode": get_val(details, "inspection-mode"),
                "SSL Profile": get_val(details, "ssl-ssh-profile"),
                "AV Profile": get_val(details, "av-profile"),
                "IPS Sensor": get_val(details, "ips-sensor"),
                "Web Filter": get_val(details, "webfilter-profile"),
                "App Control": get_val(details, "application-list"),
                "User Groups": ", ".join(get_multi(details, "groups")),
                "Users": ", ".join(get_multi(details, "users")),
            })
    df = pd.DataFrame(rows)
    df.to_csv(out/ "any_any_deny.csv", index=False)
#extracting vpns phase 1 and phase 2
def extract_vpns(data, out):
    phase1 = {}
    phase1.update(data.get("vpn_ipsec_phase1-interface", {}))
    phase1.update(data.get("vpn_ipsec_phase1_interface", {}))  
    phase1.update(data.get("vpn_ipsec_phase1", {}))
    phase2 = {}
    phase2.update(data.get("vpn_ipsec_phase2-interface", {}))
    phase2.update(data.get("vpn_ipsec_phase2_interface", {}))  
    phase2.update(data.get("vpn_ipsec_phase2", {}))
    phase1_data = {}
    for name, details in phase1.items():
        phase1_data[name.strip().lower()] = {
            "VPN_Name": name,
            "Interface": get_val(details, "interface"),
            "Remote_GW": get_val(details, "remote-gw"),
            "IKE_Version": get_val(details, "ike-version"),
            "Proposal": get_multi(details, "proposal"),
            "DH_Group": get_multi(details, "dhgrp") or "default"
        }
    rows = []
    for name, details in phase2.items():
        phase1_name = get_val(details, "phase1name").strip().lower()
        if not phase1_name:
            continue
        base = phase1_data.get(phase1_name)
        if not base:
            continue
        row = {
            **base,
            "Phase2_Name": name,
            "P2_Proposal": get_multi(details, "proposal"),
            "Src_Subnet": get_multi(details, "src-subnet"),
            "Dst_Subnet": get_multi(details, "dst-subnet"),
        }
        pfs = str(get_val(details, "pfs")).lower()
        if pfs == "enable":
            row["P2_DH_Group"] = get_multi(details, "dhgrp") or "unknown"
        else:
            row["P2_DH_Group"] = "none"
        rows.append(row)
    for p1_name, p1_data in phase1_data.items():
        found = any(
            p1_name == get_val(p2, "phase1name").strip().lower()
            for p2 in phase2.values()
        )
        if not found:
            rows.append({
                **p1_data,
                "Phase2_Name": "",
                "P2_Proposal": "",
                "Src_Subnet": "",
                "Dst_Subnet": "",
                "P2_DH_Group": ""
            })
    pd.DataFrame(rows).to_csv(out / "vpn.csv", index=False)
#Expand service group members
def resolve_services(service_list, data):
    resolved = set()
    to_process = list(service_list)
    svc_groups = {}
    svc_groups.update(data.get("firewall_service_group", {}))
    svc_groups.update(data.get("firewall_service_group_custom", {}))
    svc_groups.update(data.get("firewall_service_grp", {}))
    while to_process:
        svc = to_process.pop()
        svc_l = svc.lower()
        resolved.add(svc_l)
        if svc in svc_groups:
            members = svc_groups[svc].get("member", [])
            for m in members:
                if str(m).lower() not in resolved:
                    to_process.append(str(m))
    return resolved
#vulnerable Service (all, rdp, http) policies
def export_vuln_svc_policies(data, out):
    rows=[]
    for pid, details in data.get("firewall_policy",{}).items():
        status=get_val(details, "status")
        if status !="enable":
            continue
        svc=set(get_multi(details, "service"))
        svc_norm=resolve_services(svc,data)
        if "all" in svc_norm or "http" in svc_norm or "rdp" in svc_norm:
            rows.append({
                "Policy ID": pid,
                "UUID": get_val(details, "uuid"),
                "Name": get_val(details, "name"),
                "Status": get_val(details, "status"),
                "Src Interface": ", ".join(get_multi(details, "srcintf")),
                "Dst Interface": ", ".join(get_multi(details, "dstintf")),
                "Source Address": ", ".join(get_multi(details, "srcaddr")),
                "Destination Address": ", ".join(get_multi(details, "dstaddr")),
                "Services": ", ".join(get_multi(details, "service")),
                "Schedule": get_val(details, "schedule"),
                "Action": get_val(details, "action"),
                "NAT": get_val(details, "nat"),
                "Logging": get_val(details, "logtraffic"),
                "UTM Status": get_val(details, "utm-status"),
                "Inspection Mode": get_val(details, "inspection-mode"),
                "SSL Profile": get_val(details, "ssl-ssh-profile"),
                "AV Profile": get_val(details, "av-profile"),
                "IPS Sensor": get_val(details, "ips-sensor"),
                "Web Filter": get_val(details, "webfilter-profile"),
                "App Control": get_val(details, "application-list"),
                "User Groups": ", ".join(get_multi(details, "groups")),
                "Users": ", ".join(get_multi(details, "users")),
            })
            df=pd.DataFrame(rows)
            df.to_csv(out/ "vuln_service.csv", index=False)
#unlogged policies
def export_unlogged_policies(data, out):
    rows=[]
    for pid, details in data.get("firewall_policy",{}).items():
        status=get_val(details, "status")
        if status !="enable":
            continue
        log=set(get_multi(details, "logtraffic"))
        log_norm= {l.lower() for l in log}
        if "disable" in log_norm:
            rows.append({
                "Policy ID": pid,
                "UUID": get_val(details, "uuid"),
                "Name": get_val(details, "name"),
                "Status": get_val(details, "status"),
                "Src Interface": ", ".join(get_multi(details, "srcintf")),
                "Dst Interface": ", ".join(get_multi(details, "dstintf")),
                "Source Address": ", ".join(get_multi(details, "srcaddr")),
                "Destination Address": ", ".join(get_multi(details, "dstaddr")),
                "Services": ", ".join(get_multi(details, "service")),
                "Schedule": get_val(details, "schedule"),
                "Action": get_val(details, "action"),
                "NAT": get_val(details, "nat"),
                "Logging": get_val(details, "logtraffic"),
                "UTM Status": get_val(details, "utm-status"),
                "Inspection Mode": get_val(details, "inspection-mode"),
                "SSL Profile": get_val(details, "ssl-ssh-profile"),
                "AV Profile": get_val(details, "av-profile"),
                "IPS Sensor": get_val(details, "ips-sensor"),
                "Web Filter": get_val(details, "webfilter-profile"),
                "App Control": get_val(details, "application-list"),
                "User Groups": ", ".join(get_multi(details, "groups")),
                "Users": ", ".join(get_multi(details, "users")),
            })
            df=pd.DataFrame(rows)
            df.to_csv(out/ "unlogged.csv",index=False)
#Destination all service all accept
def export_dst_all_svc_all_accept_policies(data, out):
    rows = []
    for pid, details in data.get("firewall_policy", {}).items():
        status = get_val(details, "status")
        if status != "enable":
            continue
        svc = set(get_multi(details, "service"))
        dst = set(get_multi(details, "dstaddr"))
        action= set(get_multi(details, "action"))
        svc_norm = {s.lower() for s in svc}
        dst_norm = {d.lower() for d in dst}
        if "all" in svc_norm and "all" in dst_norm and 'accept' in action :
            rows.append({
               "Policy ID": pid,
                "UUID": get_val(details, "uuid"),
                "Name": get_val(details, "name"),
                "Status": get_val(details, "status"),
                "Src Interface": ", ".join(get_multi(details, "srcintf")),
                "Dst Interface": ", ".join(get_multi(details, "dstintf")),
                "Source Address": ", ".join(get_multi(details, "srcaddr")),
                "Destination Address": ", ".join(get_multi(details, "dstaddr")),
                "Services": ", ".join(get_multi(details, "service")),
                "Schedule": get_val(details, "schedule"),
                "Action": get_val(details, "action"),
                "NAT": get_val(details, "nat"),
                "Logging": get_val(details, "logtraffic"),
                "UTM Status": get_val(details, "utm-status"),
                "Inspection Mode": get_val(details, "inspection-mode"),
                "SSL Profile": get_val(details, "ssl-ssh-profile"),
                "AV Profile": get_val(details, "av-profile"),
                "IPS Sensor": get_val(details, "ips-sensor"),
                "Web Filter": get_val(details, "webfilter-profile"),
                "App Control": get_val(details, "application-list"),
                "User Groups": ", ".join(get_multi(details, "groups")),
                "Users": ", ".join(get_multi(details, "users")),
            })
    df = pd.DataFrame(rows)
    df.to_csv(out / "dst_all_svc_all_accept.csv", index=False)
#Destination all service all deny
def export_dst_all_svc_all_deny_policies(data, out):
    rows = []
    for pid, details in data.get("firewall_policy", {}).items():
        status = get_val(details, "status")
        if status != "enable":
            continue
        svc = set(get_multi(details, "service"))
        dst = set(get_multi(details, "dstaddr"))
        action= set(get_multi(details, "action"))
        svc_norm = {s.lower() for s in svc}
        dst_norm = {d.lower() for d in dst}
        if "all" in svc_norm and "all" in dst_norm and 'deny' in action :
            rows.append({
               "Policy ID": pid,
                "UUID": get_val(details, "uuid"),
                "Name": get_val(details, "name"),
                "Status": get_val(details, "status"),
                "Src Interface": ", ".join(get_multi(details, "srcintf")),
                "Dst Interface": ", ".join(get_multi(details, "dstintf")),
                "Source Address": ", ".join(get_multi(details, "srcaddr")),
                "Destination Address": ", ".join(get_multi(details, "dstaddr")),
                "Services": ", ".join(get_multi(details, "service")),
                "Schedule": get_val(details, "schedule"),
                "Action": get_val(details, "action"),
                "NAT": get_val(details, "nat"),
                "Logging": get_val(details, "logtraffic"),
                "UTM Status": get_val(details, "utm-status"),
                "Inspection Mode": get_val(details, "inspection-mode"),
                "SSL Profile": get_val(details, "ssl-ssh-profile"),
                "AV Profile": get_val(details, "av-profile"),
                "IPS Sensor": get_val(details, "ips-sensor"),
                "Web Filter": get_val(details, "webfilter-profile"),
                "App Control": get_val(details, "application-list"),
                "User Groups": ", ".join(get_multi(details, "groups")),
                "Users": ", ".join(get_multi(details, "users")),
            })
    df = pd.DataFrame(rows)
    df.to_csv(out / "dst_all_svc_all_deny.csv", index=False)
#detailed policy extract
def parse_policies_detailed(data):
    policies = []
    for pid, details in data.get("firewall_policy", {}).items():
        policies.append({
            "Policy ID": pid,
            "UUID": get_val(details, "uuid"),
            "Name": get_val(details, "name"),
            "Status": get_val(details, "status"),
            "Src Interface": ", ".join(get_multi(details, "srcintf")),
            "Dst Interface": ", ".join(get_multi(details, "dstintf")),
            "Source Address": ", ".join(get_multi(details, "srcaddr")),
            "Destination Address": ", ".join(get_multi(details, "dstaddr")),
            "Services": ", ".join(get_multi(details, "service")),
            "Schedule": get_val(details, "schedule"),
            "Action": get_val(details, "action"),
            "NAT": get_val(details, "nat"),
            "Logging": get_val(details, "logtraffic"),
            "UTM Status": get_val(details, "utm-status"),
            "Inspection Mode": get_val(details, "inspection-mode"),
            "SSL Profile": get_val(details, "ssl-ssh-profile"),
            "AV Profile": get_val(details, "av-profile"),
            "IPS Sensor": get_val(details, "ips-sensor"),
            "Web Filter": get_val(details, "webfilter-profile"),
            "App Control": get_val(details, "application-list"),
            "User Groups": ", ".join(get_multi(details, "groups")),
            "Users": ", ".join(get_multi(details, "users")),
        })
    return pd.DataFrame(policies)
#extract account profiles
def export_accprofiles_flat(data, out):
    rows = []
    for name, profile in data.get("system_accprofile", {}).items():
        row = {"name": name}
        for key, value in profile.items():
            if isinstance(value, dict):
                for sub_key, sub_val in value.items():
                    col_name = f"{key}_{sub_key}"

                    if isinstance(sub_val, list):
                        row[col_name] = ",".join(map(str, sub_val))
                    else:
                        row[col_name] = sub_val
            elif isinstance(value, list):
                row[key] = ",".join(map(str, value))
            else:
                row[key] = value
        rows.append(row)
    df = pd.DataFrame(rows)
    df.fillna("", inplace=True)
    df.to_csv(out/ "accprofile.csv", index=False)
# main extraction(interfaces , vlans etc)
def extract_all(data, out):
    # INTERFACES
    iface = []
    for k, v in data.get("system_interface", {}).items():
        iface.append({
            "Interface": k,
            "IP": get_val(v, "ip"),
            "Type": get_val(v, "type"),
            "Status": get_val(v, "status")
        })
    pd.DataFrame(iface).to_csv(out / "interfaces.csv", index=False)
    # VLANS
    vlans = []
    for k, v in data.get("system_interface", {}).items():
        if get_val(v, "type") == "vlan":
            vlans.append({
                "VLAN_Name": k,
                "VLAN_ID": get_val(v, "vlanid"),
                "Parent": get_val(v, "interface"),
                "IP": get_val(v, "ip")
            })
    pd.DataFrame(vlans).to_csv(out / "vlans.csv", index=False)
    # VPN
    extract_vpns(data, out)
    # interface mapping
    iface_map = {}
    interfaces = data.get("system_interface", {})
    vpn_phase1 = data.get("vpn_ipsec_phase1-interface", {})
    for name, details in interfaces.items():
        iface_map[norm(name)] = classify_interface(name, details, vpn_phase1, data)
    for name in vpn_phase1.keys():
        iface_map[norm(name)] = "INTERNAL"
    # policies traffic type
    df_detailed = parse_policies_detailed(data)
    df_detailed.to_csv(out / "policies_detailed.csv", index=False)
    policies = []
    zone_rows = []
    for pid, d in data.get("firewall_policy", {}).items():
        src_intf = get_val(d, "srcintf")
        dst_intf = get_val(d, "dstintf")
        policies.append({
            "Policy_ID": pid,
            "Action": get_val(d, "action"),
            "Src": ", ".join(get_multi(d, "srcaddr")),
            "Dst": ", ".join(get_multi(d, "dstaddr")),
            "Service": ", ".join(get_multi(d, "service"))
        })
        zone_rows.append({
            "Policy ID": pid,
            "Src Interface": src_intf,
            "Dst Interface": dst_intf,
            "Src_Zone_Type": iface_map.get(src_intf, "UNKNOWN"),
            "Dst_Zone_Type": iface_map.get(dst_intf, "UNKNOWN"),
        })
    pd.DataFrame(zone_rows).to_csv(out / "Policies_Traffic_Type.csv", index=False)
    # addresses
    addr_rows = []
    fqdn_rows = []
    for name, d in data.get("firewall_address", {}).items():
        subnet = get_multi(d, "subnet")
        fqdn = get_val(d, "fqdn")
        start = get_val(d, "start-ip")
        end = get_val(d, "end-ip")
        if fqdn:
            fqdn_rows.append({"Name": name, "FQDN": fqdn})
            continue
        if subnet:
            val = " ".join(subnet)
            typ = "subnet"
        elif start and end:
            val = f"{start} - {end}"
            typ = "range"
        else:
            val = ""
            typ = "unknown"
        addr_rows.append({
            "Name": name,
            "Type": typ,
            "Value": val
        })
    addrgrp_rows=[]
    for name, d in data.get("firewall_addrgrp", {}).items():
        members = get_multi(d, "member")
        addrgrp_rows.append({
            "Group Name": name,
            "Members": ", ".join(members) if members else ""
        })
    pd.DataFrame(addrgrp_rows).to_csv(out / "address_groups.csv", index=False)
    pd.DataFrame(addr_rows).to_csv(out / "addresses.csv", index=False)
    pd.DataFrame(fqdn_rows).to_csv(out / "fqdn.csv", index=False)
    # SYSTEM ADMINS
    grouped_admins = defaultdict(list)
    for name, details in data.get("system_admin", {}).items():
        admin = {
            "name": name,
            "accprofile": get_val(details, "accprofile"),
            "mfa": get_val(details, "two-factor"),
            "vdom": " ".join(get_multi(details, "vdom")),
        }
        profile = admin["accprofile"] or "unknown"
        grouped_admins[profile].append(admin)
    # create separate CSVs per accprofile
    for profile, records in grouped_admins.items():
        safe_profile = re.sub(r'[^a-zA-Z0-9_-]', '_', profile)
        filename = f"system_admins_{safe_profile}.csv"
        pd.DataFrame(records).to_csv(out / filename, index=False)
    # LOCAL USERS
    users = []
    for name, details in data.get("user_local", {}).items():
        mfa_raw = get_val(details, "two-factor")
        if mfa_raw and mfa_raw != "disable":
            mfa_status = "enable"
            mfa_type = mfa_raw
        else:
            mfa_status = "disable"
            mfa_type = "none"
        users.append({
            "name": name,
            "status": get_val(details, "status"),
            "auth_type": get_val(details, "type"),
            "mfa_status": mfa_status,
            "mfa_type": mfa_type,
            "password": " ".join(get_multi(details, "passwd"))
        })
    pd.DataFrame(users).to_csv(out / "local_users.csv", index=False)
    df = pd.DataFrame(users)
    # Filter enabled users without MFA
    filtered_df = df[(df["status"] == "enable") & (df["mfa_status"] == "disable")]
    df.to_csv(out / "local_users.csv", index=False)
    if not filtered_df.empty:
        filtered_df.to_csv(out / "enabled_users_no_mfa.csv", index=False)
    # USER GROUPS
    groups = []
    for name, details in data.get("user_group", {}).items():
        for m in details.get("member", []):
            groups.append({"group_name": name, "member": str(m)})
    pd.DataFrame(groups).to_csv(out / "user_groups.csv", index=False)
    # ACCESS PROFILES
    export_accprofiles_flat(data, out)
    # LDAP
    ldap_rows = [{"name": n, "server": get_val(d, "server")} for n, d in data.get("user_ldap", {}).items()]
    pd.DataFrame(ldap_rows).to_csv(out / "ldap_servers.csv", index=False)
    # RADIUS
    radius_rows = [{"name": n, "server": get_val(d, "server")} for n, d in data.get("user_radius", {}).items()]
    pd.DataFrame(radius_rows).to_csv(out / "radius_servers.csv", index=False)
    # TACACS
    tacacs_rows = [{"name": n, "server": get_val(d, "server")} for n, d in data.get("user_tacacs+", {}).items()]
    pd.DataFrame(tacacs_rows).to_csv(out / "tacacs_servers.csv", index=False)
    # SAML (SSO)
    saml_rows = [{"name": n, "idp_entity": get_val(d, "entity-id")} for n, d in data.get("user_saml", {}).items()]
    pd.DataFrame(saml_rows).to_csv(out / "saml_providers.csv", index=False)
    #Destination address all and service all accept
    export_dst_all_svc_all_accept_policies(data, out)
    #Destination all service all deny
    export_dst_all_svc_all_deny_policies(data, out)
    #source any destination any accept policies
    export_any_any_accept_policy(data, out)
    #source any destination any deny policies
    export_any_any_deny_policy(data, out)
    #unlogged policies
    export_unlogged_policies(data, out)
    #vulnerable services
    export_vuln_svc_policies(data,out)
    #services
    export_firewall_services(data, out)
    #service groups
    export_service_groups(data, out)
# policy
def build_policy_df(data):
    rows = []
    for pid, d in data.get("firewall_policy", {}).items():
        if get_val(d, "status") != "enable":
            continue
        rows.append({
            "Policy": pid,
            "Action": get_val(d, "action"),
            "src": normalize_set(get_multi(d, "srcaddr")),
            "dst": normalize_set(get_multi(d, "dstaddr")),
            "svc": normalize_set(get_multi(d, "service")),
            "srcintf": normalize_set(get_multi(d, "srcintf")),
            "dstintf": normalize_set(get_multi(d, "dstintf")),
            "users": normalize_set(get_multi(d, "users")),
            "groups": normalize_set(get_multi(d, "groups")),
            "Schedule": get_val(d, "schedule"),
        })
    return pd.DataFrame(rows)
def is_superset(earlier, later):
    if "all" in earlier:
        return True
    return later.issubset(earlier)
def schedule_match(earlier, later):
    return earlier == "always" or earlier == later
#policy analysis (subsumption and conflicts)
def analyze_policies(df):
    subs, conf = [], []
    for i in range(len(df)):
        for j in range(i):
            a, b = df.iloc[j], df.iloc[i]
            #Interface must match exactly
            if a["srcintf"] != b["srcintf"]:
                continue
            if a["dstintf"] != b["dstintf"]:
                continue
            # Schedule check (NEW)
            if not (a["Schedule"] == "always" or a["Schedule"] == b["Schedule"]): 
                continue
            # Superset logic (handles "all" properly)
            if not ("all" in a["src"] or b["src"].issubset(a["src"])): 
                continue
            if not ("all" in a["dst"] or b["dst"].issubset(a["dst"])): 
                continue
            if not ("all" in a["svc"] or b["svc"].issubset(a["svc"])): 
                continue
            if not ("all" in a["users"] or b["users"].issubset(a["users"])): 
                continue
            if not ("all" in a["groups"] or b["groups"].issubset(a["groups"])): 
                continue
            # Classification
            if a["Action"] == b["Action"]:
                subs.append({"Subsumed": b["Policy"], "By": a["Policy"]})
            else:
                conf.append({"Conflict": b["Policy"], "With": a["Policy"]})
            break
    return pd.DataFrame(subs), pd.DataFrame(conf)
def combine_csvs_to_excel(csv_dir, output_file):
    csv_dir = Path(csv_dir)
    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        for csv_file in csv_dir.glob("*.csv"):
            try:
                df = pd.read_csv(csv_file)
                sheet_name = csv_file.stem[:31]
                df.to_excel(writer, sheet_name=sheet_name, index=False)
            except pd.errors.EmptyDataError:
                continue        # skip empty files
#run extracts
def run(conf_file, output_path):
    stop, t = spin("Creating directories...")
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_dir=output_dir/ "csv_files"
    csv_dir.mkdir(parents=True, exist_ok=True)
    stop.set(); t.join()
    print("\rCreating directories...  Done")
    print("ANALYZING CONFIGURATION")
    stop, t = spin("Parsing config...")
    data = parse_config(conf_file,output_path)
    stop.set(); t.join()
    print("\rParsing config...  Done")
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_dir=output_dir/ "csv_files"
    csv_dir.mkdir(parents=True, exist_ok=True)
    stop, t = spin("Extracting data...")
    extract_all(data, csv_dir)
    stop.set(); t.join()
    print("\rExtracting data...  Done")
    stop, t = spin("Building policy dataframe...")
    df = build_policy_df(data)
    stop.set(); t.join()
    print("\rBuilding policy dataframe...  Done")
    stop, t = spin("Analyzing policies...")
    subs,conf = analyze_policies(df)
    subs.to_csv(csv_dir / "subsumed.csv", index=False)
    conf.to_csv(csv_dir / "conflicts.csv", index=False)
    stop.set();t.join()
    print("\rAnalyzing policies...  Done")
    excel_path=output_dir/ "combined_report.xlsx"
    combine_csvs_to_excel(csv_dir, excel_path)
    print("\rCOMPLETE")
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="Path to FortiGate .conf")
    parser.add_argument("--output", default="firewall_report")
    args = parser.parse_args()
    run(args.config, args.output)