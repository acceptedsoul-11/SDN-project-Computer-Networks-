# Dynamic Host Blocking System using POX (SDN)

## 📌 Overview

This project implements a **Dynamic Host Blocking System** using Software Defined Networking (SDN) with the POX controller.
It detects abnormal traffic and dynamically blocks malicious hosts by installing flow rules in the switch.

---

## 🎯 Objectives

* Monitor host traffic
* Detect high traffic behavior
* Block malicious hosts dynamically
* Verify blocking using flow rules

---

## 🛠 Requirements

* Ubuntu/Linux
* Mininet
* Open vSwitch
* POX Controller

---

## 🚀 Execution

### Start Controller

```bash
cd ~/pox
./pox.py log.level --DEBUG misc.dynamic_block
```

### Start Mininet

```bash
sudo mn --topo single,3 --controller remote --switch ovsk
```

---

## 🧪 Experiment Output

### 🔹 Step 1: Controller + Mininet Start

![Step 1](images/1.png)
*Figure 1: POX controller started and Mininet topology initialized*

---

### 🔹 Step 2: Normal Traffic

![Step 2](images/2.png)
*Figure 2: Successful ping between hosts (no packet loss)*

---

### 🔹 Step 3: Traffic Monitoring

![Step 3](images/3.png)
*Figure 3: Controller logs showing packet count per host*

---

### 🔹 Step 4: Heavy Traffic (Attack Simulation)

![Step 4](images/4.png)
*Figure 4: High traffic generated using ping flood*

---

### 🔹 Step 5: Attack Detection

![Step 5](images/5.png)
*Figure 5: Controller detects abnormal traffic*

---

### 🔹 Step 6: Blocking Action

![Step 6](images/6.png)
*Figure 6: Host is blocked after exceeding threshold*

---

### 🔹 Step 7: High Packet Loss

![Step 7](images/7.png)
*Figure 7: Packet loss observed after blocking*

---

### 🔹 Step 8: Flow Table Verification

![Step 8](images/8.png)
*Figure 8: DROP rule installed in switch flow table*

---

### 🔹 Step 9: Controller Shutdown

![Step 9](images/9.png)
*Figure 9: POX controller terminated*

---

## ⚙️ Working Principle

1. Switch sends packets to controller
2. Controller monitors traffic per host
3. If threshold exceeded:

   * Host is marked malicious
   * DROP rule is installed
4. Traffic from that host is blocked

---

## 🔧 Configuration

* `THRESHOLD` → Maximum allowed packets
* `TIME_WINDOW` → Time interval

---

## 🧹 Useful Commands

```bash
sudo mn -c              # Clear Mininet
sudo pkill -f pox       # Kill controller
sudo fuser -k 6633/tcp  # Free port
dpctl dump-flows        # View flow table
```

---

## ⚠️ Notes

* Start POX before Mininet
* Ensure port 6633 is free
* ARP packets must be forwarded

---

## 🎯 Conclusion

This project demonstrates how SDN enables **centralized control and dynamic security enforcement** by detecting and blocking malicious hosts in real-time.

---

## 👨‍💻 Author

Sai

