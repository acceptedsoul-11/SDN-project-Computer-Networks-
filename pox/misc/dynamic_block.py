# -------------------------------
# 🔹 IMPORT MODULES
# -------------------------------

from pox.core import core                     # POX core
import pox.openflow.libopenflow_01 as of      # OpenFlow
from collections import defaultdict           # Default dictionary
import time                                   # Time tracking

log = core.getLogger()                        # Logger


# -------------------------------
# 🔹 DATA STRUCTURES
# -------------------------------

packet_count = defaultdict(int)   # packet count per IP
timestamps = defaultdict(list)    # timestamps per IP
blocked_ips = set()               # blocked IP list


# -------------------------------
# 🔹 CONFIGURATION
# -------------------------------

THRESHOLD = 30     # max packets allowed
TIME_WINDOW = 5    # seconds window


# -------------------------------
# 🔹 PACKET HANDLER
# -------------------------------

def _handle_PacketIn(event):
    """
    Handles every packet sent from switch to controller
    """

    packet = event.parsed

    # -------------------------------
    # 🔹 DEFAULT FORWARDING (IMPORTANT)
    # -------------------------------
    # This ensures ARP + normal traffic works

    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    msg.data = event.ofp


    # Try extracting IPv4 packet
    ip_packet = packet.find('ipv4')

    # If NOT IP (like ARP) → just forward
    if not ip_packet:
        event.connection.send(msg)
        return


    src_ip = str(ip_packet.srcip)
    current_time = time.time()


    # -------------------------------
    # 🔹 IF BLOCKED → DROP
    # -------------------------------

    if src_ip in blocked_ips:
        log.info("[DROP] Blocked IP %s tried to send packet", src_ip)
        return


    # -------------------------------
    # 🔹 TRACK TRAFFIC
    # -------------------------------

    timestamps[src_ip].append(current_time)

    # Keep only timestamps in time window
    timestamps[src_ip] = [
        t for t in timestamps[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    packet_count[src_ip] = len(timestamps[src_ip])

    log.info("Traffic from %s = %d packets", src_ip, packet_count[src_ip])


    # -------------------------------
    # 🔹 DETECT ATTACK
    # -------------------------------

    if packet_count[src_ip] > THRESHOLD:

        log.info("[ALERT] High traffic detected from %s", src_ip)

        blocked_ips.add(src_ip)

        # Install DROP rule
        msg_block = of.ofp_flow_mod()

        msg_block.match.dl_type = 0x0800     # IPv4
        msg_block.match.nw_src = ip_packet.srcip

        msg_block.priority = 100
        msg_block.actions = []               # DROP

        event.connection.send(msg_block)

        log.info("[BLOCKED] %s is now blocked", src_ip)

        return


    # -------------------------------
    # 🔹 NORMAL FORWARDING
    # -------------------------------

    event.connection.send(msg)


# -------------------------------
# 🔹 LAUNCH CONTROLLER
# -------------------------------

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("🚀 Dynamic Host Blocking System Started")
