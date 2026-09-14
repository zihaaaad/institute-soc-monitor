# Open-Source IEEE Standards MAC OUI Hardware Vendor Database
# Curated for Educational Institutes, Enterprise LANs, and Network SOCs

IEEE_OUI_DATABASE = {
    # Virtualization & Cloud Hypervisors
    "00:50:56": "VMware ESXi / Workstation",
    "00:0c:29": "VMware Virtual Machine",
    "00:05:69": "VMware Infrastructure",
    "00:15:5d": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "00:16:3e": "Xen Virtual Machine",
    "02:42:ac": "Docker Container Bridge",

    # Major PC & Motherboard Manufacturers
    "10:7c:61": "Intel Corporate LAN",
    "00:1b:21": "Intel Gigabit NIC",
    "00:1e:67": "Intel Desktop Board",
    "34:5a:60": "Realtek Semiconductor",
    "b0:19:21": "Realtek PCIe GBE Family",
    "00:e0:4c": "Realtek Fast Ethernet",
    "4c:ed:fb": "Realtek Wireless LAN",
    "e4:54:e8": "Dell Inc.",
    "00:14:22": "Dell Enterprise Systems",
    "18:03:73": "Dell OptiPlex / Latitude",
    "b8:ac:6f": "Dell Alienware / Precision",
    "70:85:c2": "HP Inc. (Hewlett-Packard)",
    "00:1e:0b": "HP ProLiant / ProDesk",
    "3c:52:82": "HP EliteBook / Pavilion",
    "08:bf:b8": "ASRock Incorporation",
    "70:4d:7b": "ASUS (ASUSTeK Computer)",
    "04:d9:f5": "ASUS ROG / TUF Gaming",
    "54:04:a6": "ASUS Motherboards",
    "ac:e0:10": "MSI (Micro-Star Int.)",
    "d8:5e:d3": "MSI Gaming Series",
    "e0:d5:5e": "Gigabyte Technology",
    "1c:1b:0d": "Gigabyte AORUS / Ultra",
    "54:ee:75": "Lenovo Group",
    "28:d0:ea": "Lenovo ThinkPad / ThinkCentre",
    "e0:d5:5e": "Lenovo IdeaPad Series",
    "50:eb:f6": "Acer Inc.",
    "00:16:76": "Acer Predator / Aspire",

    # Network Infrastructure & Core Routers / Switches
    "d4:01:c3": "Cisco Systems",
    "00:00:0c": "Cisco Router / Catalyst",
    "00:1b:d4": "Cisco Catalyst Switch",
    "64:d8:14": "Cisco Meraki Cloud AP",
    "00:80:91": "D-Link Systems",
    "14:d6:4d": "D-Link Gigabit Switch",
    "50:c7:bf": "TP-Link Technologies",
    "ec:08:6b": "TP-Link Archer / Omada",
    "30:b5:c2": "TP-Link JetStream Switch",
    "48:8f:5a": "MikroTik RouterOS",
    "cc:2d:e0": "MikroTik Cloud Core Router",
    "74:4d:28": "Ubiquiti Networks (UniFi)",
    "fc:ec:da": "Ubiquiti UniFi Access Point",
    "00:17:88": "Philips Hue / IoT Gateway",
    "00:24:b2": "Netgear Inc.",
    "a0:04:60": "Netgear ProSafe Switch",
    "00:04:96": "Extreme Networks",
    "00:0b:86": "Aruba Networks (HPE)",

    # Mobile & Smart Devices (Common Rogue Devices)
    "a4:83:e7": "Apple Inc. (MacBook/iPhone)",
    "f0:18:98": "Apple iPhone / iPad",
    "3c:06:30": "Apple Silicon (M1/M2/M3)",
    "ac:bc:32": "Apple Mac mini / Studio",
    "00:26:08": "Apple iMac Desktop",
    "88:36:5f": "Samsung Electronics",
    "50:01:d9": "Samsung Galaxy Device",
    "78:02:f8": "Xiaomi Communications",
    "28:6c:07": "Xiaomi Redmi / POCO",
    "60:ab:67": "OnePlus Technology",
    "70:70:8b": "Huawei Technologies",
    "28:ff:3e": "Huawei Honor / Mate",
    "00:1a:11": "Google LLC (Pixel / Nest)",
    "d8:3c:69": "Sony Corporation",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi 4 Model B",
    "e4:5f:01": "Raspberry Pi 5 / Zero",
    "24:0a:c4": "Espressif Systems (ESP32 / ESP8266 IoT)"
}

def lookup_mac_vendor(mac_address: str) -> str:
    """Resolves MAC address against open-source IEEE OUI Database."""
    if not mac_address or mac_address in ("static/lan", "dynamic/lan"):
        return "Generic Network Device"
    
    clean_mac = mac_address.lower().replace("-", ":")
    prefix_6 = clean_mac[:8] # e.g. '00:50:56'
    
    if prefix_6 in IEEE_OUI_DATABASE:
        return IEEE_OUI_DATABASE[prefix_6]
    
    # Fallback to general category matching
    if clean_mac.startswith("00:"):
        return "Legacy Ethernet Device"
    
    return "Standard PC / NIC"
