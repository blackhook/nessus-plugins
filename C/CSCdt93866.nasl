#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#

include("compat.inc");

if (description)
{
 script_id(10982);
 script_version("1.24");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

 script_cve_id("CVE-2001-0414");
 script_bugtraq_id(2540);
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt93866");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20020508-ntp-vulnerability");

 script_name(english:"Cisco NTP ntpd readvar Variable Remote Overflow (CSCdt93866)");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
"By sending a crafted NTP control packet, it is possible to trigger a
buffer overflow in the NTP daemon.  This vulnerability can be exploited
remotely.  The successful exploitation may cause arbitrary code to be
executed on the target machine. 

This vulnerability is documented as Cisco Bug ID CSCdt93866. 

An attacker may use this flaw to execute arbitrary code on the remote
host (although it's not believed to be doable)");
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020508-ntp-vulnerability
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?033c44be");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20020508-ntp-vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'NTP Daemon readvar Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CISCO");

 script_dependencies("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}

# The code starts here

ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 10.3
if(egrep(string:os, pattern:"(^|\s+)(10\.3\([0-9]*\)|10\.3),"))ok=1;

# 11.0
if(egrep(string:os, pattern:"(^|\s+)(11\.0\([0-9]*\)|11\.0),"))ok=1;

# 11.1
if(egrep(string:os, pattern:"(^|\s+)(11\.1\([0-9]*\)|11\.1),"))ok=1;

# 11.1AA
if(egrep(string:os, pattern:"(^|\s+)(11\.1\([0-9]*\)|11\.1)AA[0-9]*,"))ok=1;

# 11.1CA
if(egrep(string:os, pattern:"(^|\s+)(11\.1\([0-9]*\)|11\.1)CA[0-9]*,"))ok=1;

# 11.1CC
if(egrep(string:os, pattern:"(^|\s+)((11\.1\(([0-9]|[1-2][0-9]|3[0-5])\)|11\.1)CC[0-9]*|11\.1\(36\)CC[0-1]),"))ok=1;

# 11.1CT
if(egrep(string:os, pattern:"(^|\s+)(11\.1\([0-9]*\)|11\.1)CT[0-9]*,"))ok=1;

# 11.1IA
if(egrep(string:os, pattern:"(^|\s+)(11\.1\([0-9]*\)|11\.1)IA[0-9]*,"))ok=1;

# 11.2
if(egrep(string:os, pattern:"(^|\s+)(11\.2\(([0-9]|[1-1][0-9]|2[0-5])\)|11\.2),"))ok=1;

# 11.2BC
if(egrep(string:os, pattern:"(^|\s+)(11\.2\([0-9]*\)|11\.2)BC[0-9]*,"))ok=1;

# 11.2F
if(egrep(string:os, pattern:"(^|\s+)(11\.2\([0-9]*\)|11\.2)F[0-9]*,"))ok=1;

# 11.2GS
if(egrep(string:os, pattern:"(^|\s+)(11\.2\([0-9]*\)|11\.2)GS[0-9]*,"))ok=1;

# 11.2P
if(egrep(string:os, pattern:"(^|\s+)(11\.2\([0-9]*\)|11\.2)P[0-9]*,"))ok=1;

# 11.2SA
if(egrep(string:os, pattern:"(^|\s+)(11\.2\([0-9]*\)|11\.2)SA[0-9]*,"))ok=1;

# 11.2WA4
if(egrep(string:os, pattern:"(^|\s+)(11\.2\([0-9]*\)|11\.2)WA4[0-9]*,"))ok=1;

# 11.2XA
if(egrep(string:os, pattern:"(^|\s+)(11\.2\([0-9]*\)|11\.2)XA[0-9]*,"))ok=1;

# 11.3
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3),"))ok=1;

# 11.3AA
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)AA[0-9]*,"))ok=1;

# 11.3DA
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)DA[0-9]*,"))ok=1;

# 11.3DB
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)DB[0-9]*,"))ok=1;

# 11.3HA
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)HA[0-9]*,"))ok=1;

# 11.3MA
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)MA[0-9]*,"))ok=1;

# 11.3NA
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)NA[0-9]*,"))ok=1;

# 11.3T
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)T[0-9]*,"))ok=1;

# 11.3XA
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)XA[0-9]*,"))ok=1;

# 11.3WA4
if(egrep(string:os, pattern:"(^|\s+)(11\.3\([0-9]*\)|11\.3)WA4[0-9]*,"))ok=1;

# 12.0
if(egrep(string:os, pattern:"(^|\s+)(12\.0\(([0-9]|1[0-7])\)|12\.0),"))ok=1;

# 12.0DA
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)DA[0-9]*,"))ok=1;

# 12.0DB
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)DB[0-9]*,"))ok=1;

# 12.0DC
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)DC[0-9]*,"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"(^|\s+)(12\.0\(([0-9]|1[0-7])\)|12\.0)S[0-9]*,"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"(^|\s+)(12\.0\(([0-9]|1[0-5])\)|12\.0)SC[0-9]*,"))ok=1;

# 12.0SL
if(egrep(string:os, pattern:"(^|\s+)((12\.0\(([0-9]|1[0-6])\)|12\.0)SL[0-9]*|12\.0\(17\)SL[0-1]),"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(^|\s+)((12\.0\(([0-9]|1[0-6])\)|12\.0)ST[0-9]*|12\.0\(17\)ST[0-0]),"))ok=1;

# 12.0T
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)T[0-9]*,"))ok=1;

# 12.0W5
if(egrep(string:os, pattern:"(^|\s+)(12\.0\(([0-9]|1[0-5])\)|12\.0)W5[0-9]*,"))ok=1;

# 12.0WC
if(egrep(string:os, pattern:"(^|\s+)((12\.0\([0-4]\)|12\.0)WC[0-9]*|12\.0\(5\)WC[0-1]),"))ok=1;

# 12.0WT
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)WT[0-9]*,"))ok=1;

# 12.0XA
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XA[0-9]*,"))ok=1;

# 12.0XB
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XB[0-9]*,"))ok=1;

# 12.0XC
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XC[0-9]*,"))ok=1;

# 12.0XD
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XD[0-9]*,"))ok=1;

# 12.0XE
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XE[0-9]*,"))ok=1;

# 12.0XF
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XF[0-9]*,"))ok=1;

# 12.0XG
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XG[0-9]*,"))ok=1;

# 12.0XH
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XH[0-9]*,"))ok=1;

# 12.0XI
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XI[0-9]*,"))ok=1;

# 12.0XJ
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XJ[0-9]*,"))ok=1;

# 12.0XJ
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XJ[0-9]*,"))ok=1;

# 12.0XK
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XK[0-9]*,"))ok=1;

# 12.0XL
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XL[0-9]*,"))ok=1;

# 12.0XM
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XM[0-9]*,"))ok=1;

# 12.0XN
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XN[0-9]*,"))ok=1;

# 12.0XP
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XP[0-9]*,"))ok=1;

# 12.0XQ
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XQ[0-9]*,"))ok=1;

# 12.0XR
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XR[0-9]*,"))ok=1;

# 12.0XS
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XS[0-9]*,"))ok=1;

# 12.0XU
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XU[0-9]*,"))ok=1;

# 12.0XV
if(egrep(string:os, pattern:"(^|\s+)(12\.0\([0-9]*\)|12\.0)XV[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-8]\)|12\.1),"))ok=1;

# 12.1AA
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-8]\)|12\.1)AA[0-9]*,"))ok=1;

# 12.1CX
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-6]\)|12\.1)CX[0-9]*,"))ok=1;

# 12.1DA
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-6]\)|12\.1)DA[0-9]*|12\.1\(7\)DA[0-1]),"))ok=1;

# 12.1DB
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-1]\)|12\.1)DB[0-9]*,"))ok=1;

# 12.1DC
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)DC[0-9]*,"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-8]\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-6]\)|12\.1)EC[0-9]*,"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-8]\)|12\.1)EX[0-9]*,"))ok=1;

# 12.1EY
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-5]\)|12\.1)EY[0-9]*,"))ok=1;

# 12.1EZ
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-5]\)|12\.1)EZ[0-9]*|12\.1\(6\)EZ[0-1]),"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)T[0-9]*|12\.1\(5\)T[0-8]),"))ok=1;

# 12.1XA
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XA[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

# 12.1XD
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XD[0-9]*,"))ok=1;

# 12.1XE
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XE[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XF[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1XI
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XI[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XK
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XK[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)XM[0-9]*|12\.1\(5\)XM[0-3]),"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)XP[0-9]*|12\.1\(5\)XP[0-3]),"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XR
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XR[0-9]*,"))ok=1;

# 12.1XS
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)XS[0-9]*|12\.1\(5\)XS[0-1]),"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XT[0-9]*,"))ok=1;

# 12.1XU
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XU[0-9]*,"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XV[0-9]*,"))ok=1;

# 12.1XW
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XW[0-9]*,"))ok=1;

# 12.1XX
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XX[0-9]*,"))ok=1;

# 12.1XY
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XY[0-9]*,"))ok=1;

# 12.1XZ
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)XZ[0-9]*,"))ok=1;

# 12.1YA
if(egrep(string:os, pattern:"(^|\s+)(12\.1\([0-9]*\)|12\.1)YA[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)YB[0-9]*|12\.1\(5\)YB[0-3]),"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)YC[0-9]*|12\.1\(5\)YC[0-0]),"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)YD[0-9]*|12\.1\(5\)YD[0-1]),"))ok=1;

# 12.1YF
if(egrep(string:os, pattern:"(^|\s+)((12\.1\([0-4]\)|12\.1)YF[0-9]*|12\.1\(5\)YF[0-1]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-2]\)|12\.2),"))ok=1;

# 12.2B
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-1]\)|12\.2)B[0-9]*,"))ok=1;

# 12.2PB
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-3]\)|12\.2)PB[0-9]*,"))ok=1;

# 12.2PI
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-1]\)|12\.2)PI[0-9]*,"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-1]\)|12\.2)S[0-9]*,"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-3]\)|12\.2)T[0-9]*,"))ok=1;

# 12.2XA
if(egrep(string:os, pattern:"(^|\s+)((12\.2\([0-1]\)|12\.2)XA[0-9]*|12\.2\(2\)XA[0-0]),"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"(^|\s+)((12\.2\([0-0]\)|12\.2)XD[0-9]*|12\.2\(1\)XD[0-0]),"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-0]\)|12\.2)XE[0-9]*,"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-0]\)|12\.2)XH[0-9]*,"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"(^|\s+)(12\.2\([0-0]\)|12\.2)XQ[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
