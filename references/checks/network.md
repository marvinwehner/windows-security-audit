# Network and firewall

Background for these findings: Windows classifies each network as **Public** (other devices are not trusted;
Windows' own sharing features are off) or **Private** (trusted home network). When an app first wants to
accept incoming connections, Windows asks whether to allow it and pre-selects the type of the network you
are on at that moment, so on a "Public" network the app is allowed on all public networks (cafés, hotels,
work guest Wi-Fi). Internet traffic from outside normally cannot reach the PC through the home router; the
risk is other devices on the same network.

## NET-04 · Apps allowed through the firewall on public networks
**What it is:** The listed apps may accept incoming connections on any port, also on public networks.
**Why it matters:** If such an app has a security hole, or runs a development server, other devices on the
same network can reach it. On a device that stays at home that means only your own devices (and guests on
your Wi-Fi); on a travelling laptop it means strangers on public Wi-Fi.
**Recommendation:** Untick "Public" for apps that do not need incoming connections there. Developer tools
(Node.js, Python, .NET, Java, Docker, VS Code) usually only need `localhost`, which never needs a rule.
Games and Steam need it only for hosting, LAN play or Remote Play.
**If you change it:** If an app later needs incoming connections, Windows asks again. Features like hosting a
game, Steam Remote Play, Spotify Connect or testing a dev server from your phone stop working on networks
where the app is not allowed.
**Fix:** guided.
1. Windows Security > Firewall & network protection > Allow an app through firewall > Change settings.
2. For each listed app, untick "Public" (keep "Private" if you use the feature at home and your home network
   is set to Private), or remove apps you no longer use.
**Undo:** tick the box again.
**Learn more:** https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/

## NET-05 · Firewall rules for programs that no longer exist
**What it is:** Uninstalled programs often leave their firewall rules behind.
**Why it matters:** A rule allows whatever program sits at that path. Rules for folders that ordinary users
can write to (for example in AppData or Downloads) let any file placed there through the firewall.
**Recommendation:** Delete the leftover rules.
**If you change it:** Nothing; the programs are gone. If you reinstall one, Windows asks again.
**Fix:** guided.
1. Press Win+R, type `wf.msc`, Enter (Windows Defender Firewall with Advanced Security).
2. In "Inbound Rules" and "Outbound Rules", sort by the "Program" column, select the rules whose program
   path is listed in the finding, and press Delete.
**Undo:** not needed; the programs no longer exist.
**Learn more:** https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/

## NET-16 · LLMNR name resolution
**What it is:** LLMNR is an old way for Windows to find other computers by name on the local network by
asking all devices "who is called X?".
**Why it matters:** Any device on the network can answer "that's me". Attack tools do exactly this to make
the PC send its login hash (a scrambled form of the password) to them, which can then be cracked or reused.
**Recommendation:** Turn it off. Modern networks use DNS and mDNS (`name.local`) instead.
**If you change it:** Very old devices without DNS can no longer be reached by their bare name (e.g.
`\\nas`); use the IP address or `nas.local` instead.
**Fix:** automatic: sets the policy `EnableMulticast = 0` (needs one administrator prompt). The port may stay
open until the next restart.
**Undo:** automatic (restores the previous policy value or removes it).
**Learn more:** https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient

## NET-17 · NetBIOS over TCP/IP
**What it is:** NetBIOS is an even older name and file-sharing protocol (ports 137 to 139), switched on per
network adapter.
**Why it matters:** Like LLMNR, it can be abused on the local network to capture login hashes, and it
reveals the PC's name and user names to the network.
**Recommendation:** Turn it off on all network adapters. Windows creates new virtual adapters (WSL, Hyper-V,
Docker) with NetBIOS on; those only reach local virtual machines and are reported as info.
**If you change it:** Very old NAS boxes, printers or Windows XP-era PCs may no longer be found by name in
Explorer's "Network" view; access them by IP address. New network adapters you add later start with
NetBIOS on again.
**Fix:** guided.
1. Press Win+R, type `ncpa.cpl`, Enter.
2. For each adapter listed in the finding: right-click > Properties > "Internet Protocol Version 4
   (TCP/IPv4)" > Properties > Advanced > WINS tab > "Disable NetBIOS over TCP/IP" > OK.
**Undo:** choose "Default" in the same place.
**Learn more:** https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration
