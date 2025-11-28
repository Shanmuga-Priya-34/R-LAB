# **R-LAB: Restricted-LAB Exam Monitoring**

R-LAB is a lightweight security framework designed to **monitor, detect, and prevent unauthorized device access** on a Linux system. It focuses on safeguarding endpoints by identifying suspicious USB events and blocking unknown peripherals before data theft or malware injection can occur.

---

## **Key Features**
- **Real-time USB Device Monitoring**
  Detects newly connected USB devices using `pyudev`.
- **Authorization-Based Access Control**
  Allows only whitelisted devices; blocks all unknown or suspicious hardware.
- **Instant Notifications**
  Alerts the user immediately when unauthorized devices are connected.
- **Modular Code Structure**
  Clean and extensible Python modules for easy customization and upgrades.
- **Lightweight & Fast**
  Minimal overhead, suitable for both personal and academic security projects.

---

## **Installation**
### **1. Install Dependencies**
```bash
sudo pip install pyudev
```

### **2. Run the System**
```bash
sudo python3 main.py
```

*Root privileges are recommended to monitor low-level hardware events.*

---

## **Working**
1. The system listens for USB add/remove events via Linux’s udev subsystem.  
2. When a device connects:
   - Its Vendor ID (VID) and Product ID (PID) are extracted.
   - The device is verified against an authorized list.
   - If allowed → access granted.
   - If unknown → device is blocked + alert triggered.
3. Logs are stored for forensic analysis.

---

## **Add Authorized Devices - Whitelisting**
Modify `allowed_devices.json`:
```json
{
  "allowed": [
    {"vendor_id": "1234", "product_id": "5678"}
  ]
}
```

---

## ** Future Enhancements**
- Network intrusion detection (NIDS)
- LAN traffic pattern analysis
- Automated firewall rule generation
- Device fingerprinting based on serial numbers

---

## **License**
This project is open-source and available under the **MIT License**.

---

## **Author**
**Shanmuga Priya G**  


