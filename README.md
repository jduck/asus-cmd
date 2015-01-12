ASUS Router infosvr UDP Broadcast root Command Execution
========================================================

Several models of ASUS's routers include a service called *infosvr* that listens on UDP broadcast port 9999 on the LAN or WLAN interface. It's used by one of ASUS's tools to ease router configuration by automatically locating routers on the local subnet. This service runs with *root* privileges and contains an unauthenticated command execution vulnerability. The source code for this service, as well as the rest of the router, is available from [ASUS's Support Site](http://support.asus.com/).

CVE
---
The CVE assigned to this issue is CVE-2014-9583 (alas, not CVE-2014-10000 after all :-/).

Affected Versions
-----------------
Currently, all known firmware versions for applicable routers (RT-AC66U, RT-N66U, etc.) are assumed vulnerable. Testing was performed against 3.0.0.376.2524-g0013f52.

The following routers/firmware versions are confirmed vulnerable:

Router   | Firmware Version          | Verified By
-------- | ------------------------- | ------------------------
RT-N66U  | 3.0.0.4.376_1071-g8696125 | Friedrich Postelstorfer
RT-AC87U | 3.0.0.4.378_3754          | David Longenecker
RT-N56U  | 3.0.0.4.374_5656          | @argilo

Technical Details
-----------------
Consider the following excerpt from the [ASUSWRT-Merlin project](https://github.com/RMerl/asuswrt-merlin), which is an enhanced fork of ASUS's code. You can view the file in it's entirety (recommended for extra lulz) [here](https://github.com/RMerl/asuswrt-merlin/blob/9ebbc9dcab0b1243d703984aa02dbdb7093ccc12/release/src/router/infosvr/common.c).

```c
   177  char *processPacket(int sockfd, char *pdubuf)
   178  {
   ...
   202      phdr = (IBOX_COMM_PKT_HDR *)pdubuf;
   ...
   207      if (phdr->ServiceID==NET_SERVICE_ID_IBOX_INFO &&
   208          phdr->PacketType==NET_PACKET_TYPE_CMD)
   209      {
   ...
```

The *processPacket* function is called after receiving a packet of *INFO_PDU_LENGTH* (512) bytes. The specific vulnerable code path is *main*->*processReq*->*processPacket*. The service then casts the packet to a structure and checks that the *ServiceID* and *PacketType* fields match expected values.

The following block contains what is believed to be the root cause of this vulnerability.

```c
   222          if (phdr->OpCode!=NET_CMD_ID_GETINFO && phdr->OpCode!=NET_CMD_ID_GETINFO_MANU)
   223          {
   224                  phdr_ex = (IBOX_COMM_PKT_HDR_EX *)pdubuf;       
   225                  
   226                  // Check Mac Address
   227                  if (memcpy(phdr_ex->MacAddress, mac, 6)==0)
   228                  {
   229                          _dprintf("Mac Error %2x%2x%2x%2x%2x%2x\n",
   230                                  (unsigned char)phdr_ex->MacAddress[0],
   231                                  (unsigned char)phdr_ex->MacAddress[1],
   232                                  (unsigned char)phdr_ex->MacAddress[2],
   233                                  (unsigned char)phdr_ex->MacAddress[3],
   234                                  (unsigned char)phdr_ex->MacAddress[4],
   235                                  (unsigned char)phdr_ex->MacAddress[5]
   236                                  );
   237                          return NULL;
   238                  }
   239                  
   240                  // Check Password
   241                  //if (strcmp(phdr_ex->Password, "admin")!=0)
   242                  //{
   243                  //      phdr_res->OpCode = phdr->OpCode | NET_RES_ERR_PASSWORD;
   244                  //      _dprintf("Password Error %s\n", phdr_ex->Password);     
   245                  //      return NULL;
   246                  //}
   247                  phdr_res->Info = phdr_ex->Info;
   248                  memcpy(phdr_res->MacAddress, phdr_ex->MacAddress, 6);
   249          }
```

The block starts off by excluding a couple of *OpCode* values, which presumably do not require authentication by design. Then, it calls the *memcpy* and suspiciously checks the return value against zero. This is highly indicative that the author intended to use *memcmp* instead. That said, even if this check was implemented properly, knowing the device's MAC address is hardly sufficient authentication.

The following block is commented out, but shows that the author at some point experimented with checking a password. Albeit, in this case, the password was hardcoded as "admin".

Moving on, the following switch statement dispatches processing based on the supplied *OpCode*.

```c
   251          switch(phdr->OpCode)
   252          {
   ...
   428                  case NET_CMD_ID_MANU_CMD:
   429                  {
   430                       #define MAXSYSCMD 256
   431                       char cmdstr[MAXSYSCMD];
   432                       PKT_SYSCMD *syscmd;
   ...
   440                       syscmd = (PKT_SYSCMD *)(pdubuf+sizeof(IBOX_COMM_PKT_HDR_EX));
   ...
   443                       if (syscmd->len>=MAXSYSCMD) syscmd->len=MAXSYSCMD;
   444                       syscmd->cmd[syscmd->len]=0;
   445                       syscmd->len=strlen(syscmd->cmd);
   446                       fprintf(stderr,"system cmd: %d %s\n", syscmd->len, syscmd->cmd);
   447  #if 0
   ...
   512  #endif
   513                       {
   514                          sprintf(cmdstr, "%s > /tmp/syscmd.out", syscmd->cmd);
   515                          system(cmdstr);
```

If an attacker specifies the *OpCode* value of *NET_CMD_ID_MANU_CMD*, the preceding block processes the packet by casting it to a *PKT_SYSCMD* structure. As such, any members of *syscmd* are fully controlled by the attacker. Before taking care (**wink**) to NULL terminate the command string, the author executes the command on line 514. Following executing the command, the output is read from the temporary file and sent back to the source address of the initiating packet.

Recommendations
---------------
Remove the remote command execution functionality from this service. Even if it were guarded with strong authentication, broadcasting a password to the entire local network isn't really something to be desired. If command execution is truly desired it should be provided via SSH or similar secure mechanism.

Workaround
----------
David Longenecker recommends using a script (JFFS) in combination with the *script_usbmount* nvram setting to kill the *infosvr* process on boot. For more information check out [his blog post](http://dnlongen.blogspot.com/2015/01/asus-bug-lets-those-on-your-local.html).

Eric Sauvageau (@RMerl) recommends firewalling port 9999 off. For more information see [his post](http://forums.smallnetbuilder.com/showthread.php?t=21774) on the Small Net Builder forum.

Alternatively, disable the *infosvr* service by killing the process after each boot. For extra fun/irony, use the exploit to do this:

```
$ ./asus-cmd "killall -9 infosvr"
[...]
```

NOTE: you won't get response to this command. Again, this will need to be done each time the device restarts.

Exploit
-------
The repository in which this advisory resides contains a working exploit for this issue.

Example exploit output:
-----------------------

```
$ ./asus-cmd "nvram show | grep -E '(firmver|buildno|extendno)'"
[*] sent command: nvram show | grep -E '(firmver|buildno|extendno)'
[!] received 512 bytes from 10.0.0.2:37625
    0c 15 0033 54ab7bc4 41:41:41:41:41:41
    0031 nvram show | grep -E '(firmver|buildno|extendno)'
[!] received 512 bytes from 10.0.0.1:9999
    0c 16 0033 54ab7bc4 xx:xx:xx:xx:xx:xx
    004e buildno=376
extendno_org=2524-g0013f52
extendno=2524-g0013f52
firmver=3.0.0.4
```

Other Links
-----------

"ASUSWRT 3.0.0.4.376_1071 - LAN Backdoor Command Execution"<br />
(this triggered my publishing. his exploit is also mirrored in the others/ directory)<br />
http://www.exploit-db.com/exploits/35688/

"SECURITY: LAN-side security hole - mitigation"<br />
http://forums.smallnetbuilder.com/showthread.php?t=21774

"Got an Asus router? Someone on your network can probably hack it"<br />
http://arstechnica.com/security/2015/01/got-an-asus-router-someone-on-your-network-can-probably-hack-it/

"ASUS bug lets those on your local network own your wireless router"<br />
http://dnlongen.blogspot.com/2015/01/asus-bug-lets-those-on-your-local.html

"Exploit allows Asus routers to be hacked from local network"<br />
http://www.itworld.com/article/2867255/exploit-allows-asus-routers-to-be-hacked-from-local-network.html

"Asus Wireless Routers Can Be Exploited By Anyone Inside the Network"<br />
http://it.slashdot.org/story/15/01/09/1349229/asus-wireless-routers-can-be-exploited-by-anyone-inside-the-network

