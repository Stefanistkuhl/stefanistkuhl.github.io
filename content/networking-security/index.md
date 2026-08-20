+++
title = 'Networking & Security'
description = 'Selected network engineering, Linux, infrastructure, and security work by Veya Fürst.'
+++

<div class="networking-intro">
  <p class="networking-kicker">Selected work</p>
  <p class="networking-lede">I build and troubleshoot networks from Ethernet frames upward. My work combines Linux networking, packet analysis, infrastructure automation, and software built to make network systems easier to test and operate.</p>
</div>

## Current project

<div class="networking-feature">
  <div>
    <p class="networking-label">Network emulation · Go · Linux</p>
    <h3><a href="https://github.com/tethux/tethux">tethux</a></h3>
    <p>A network-emulation toolkit for programmable Ethernet topologies spanning containers, virtual machines, and physical hosts.</p>
    <p>I work on Ethernet switching, Linux network namespaces, TAP interfaces, UDP tunnels, raw sockets, PCAP transports, container runtimes, reproducible NixOS test environments, and observability.</p>
  </div>
  <div class="networking-stack">Ethernet<br>namespaces<br>PCAP<br>Docker · Podman · containerd</div>
</div>

## Networking and security labs

These are selected HTL Donaustadt labs. They are coursework, presented here because they show hands-on configuration, investigation, and documentation rather than just a list of technologies.

<article class="lab-flagship">
  <img src="https://raw.githubusercontent.com/0xveya/goobering/master/itsi/y4/ex1/images/itsi-ex1.svg" alt="Distributed Anti Hardening lab topology">
  <div>
    <p class="networking-label">Flagship lab · distributed systems security</p>
    <h3>Anti Hardening</h3>
    <p>Designed, deployed, deliberately weakened, attacked, and then hardened a distributed application spanning a k3s cluster, a Go API, PostgreSQL, Docker Swarm secrets, JWT authentication, Tailscale, and Windows Server backups.</p>
    <p>The lab covers authentication bypasses, CSP and XSS, secret management, database exposure, encrypted service connectivity, access control, backup design, and the tradeoffs between insecure and hardened deployments.</p>
    <a class="lab-action" href="/posts/itsi/year-4/exercise-1/anti-hardening/">Read the full lab <span aria-hidden="true">→</span></a>
  </div>
</article>

<div class="lab-grid">
  <a class="lab-card" href="/posts/itsi/year-3/exercise-10/capturing-network-traffic/">
    <img src="https://raw.githubusercontent.com/0xveya/goobering/master/itsi/y3/ex10/images/topo11.png" alt="Network topology used for packet capture and traffic analysis">
    <span class="networking-label">Packet analysis · Wireshark · RouterOS</span>
    <strong>Capturing Network Traffic</strong>
    <span>Port mirroring and packet-level analysis of ICMP, plaintext HTTP authentication, and VoIP traffic.</span>
  </a>
  <a class="lab-card" href="/posts/itsi/year-3/exercise-11/wlan-setup-and-security/">
    <img src="https://raw.githubusercontent.com/0xveya/goobering/master/itsi/y3/ex11/images/topo.png" alt="Wireless networking lab topology">
    <span class="networking-label">Wireless · WPA · Wireshark</span>
    <strong>WLAN Setup and Security</strong>
    <span>DHCP, access-point configuration, client isolation, deauthentication frames, and WPA handshake analysis.</span>
  </a>
  <a class="lab-card" href="/posts/itsi/year-3/exercise-6/linux-hardening-nginx/">
    <img src="https://raw.githubusercontent.com/0xveya/goobering/master/itsi/y3/ex6/images/topology.png" alt="Linux web server hardening lab topology">
    <span class="networking-label">Linux · NGINX · TLS · SSH</span>
    <strong>Hardening a Linux Webserver</strong>
    <span>Service isolation, SSH key authentication, HTTP authentication, TLS, and local DNS in a containerized lab.</span>
  </a>
</div>

## Practical background

- First-level IT support experience with Windows workstations, hardware and software troubleshooting, deployments, and rollout automation.
- HTL focus in networking, IT security, and systems administration, followed by project-based systems programming at 42 Vienna.
- Three student CTF events organized with networking, Linux, web, and security challenges.
- A private homelab running container infrastructure, network services, reverse proxies, and automation.

You can find the rest of my work on [GitHub](https://github.com/0xveya).
