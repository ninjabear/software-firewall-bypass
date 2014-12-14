SoftwareFirewallBypass
======================

Finds a trusted process (one with an open socket handle) and uses process injection to leverage it's trust setting.

This was designed against tools like ZoneAlarm which users "trust" to open a socket. As the process is altered in memory
the hash of the executable on disc doesn't change, therefore it wasn't registered as modified.

This worked on XP. I suspect with UAC it no longer works.
