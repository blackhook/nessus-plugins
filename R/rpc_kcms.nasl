#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# This script was written by Michael Scheidell  <scheidell at secnap.net>
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10832);
 script_version("1.21");
 script_cve_id("CVE-2001-0595");
 script_bugtraq_id(2605);

 script_name(english:"Kcms Profile Server");
 
 desc["english"] = "
The Kodak Color Management System service is running.
The KCMS service on Solaris 2.5 could allow a local user
to write to arbitrary files and gain root access.

*** This warning may be a false 
*** positive since the presence
*** of the bug has not been tested.

Patches: 107337-02 SunOS 5.7 has been released
and the following should be out soon:
111400-01 SunOS 5.8, 111401-01 SunOS 5.8_x86

See also: http://archives.neohapsis.com/archives/bugtraq/2001-04/0203.html
http://www.packetstormsecurity.org/advisories/ibm-ers/96-09
http://research.eeye.com/html/advisories/published/AD20010409.html

Solution : Disable suid, side effects are minimal.

Risk factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"Checks the presence of a Kcms service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2019 Michael Scheidell");
 script_family(english:"RPC");
 if ( !defined_func("bn_random") ) 
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl");
 else
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl", "solaris251_103879.nasl", "solaris251_x86_103881.nasl", "solaris26_107336.nasl", "solaris26_x86_107338.nasl", "solaris7_107337.nasl", "solaris7_x86_107339.nasl", "solaris8_111400.nasl", "solaris8_x86_111401.nasl", "solaris9_114636.nasl", "solaris9_x86_114637.nasl" );
 script_require_keys("rpc/portmap");
 exit(0);
}

include("compat.inc");

if ( report_paranoia < 2 ) exit(0);


version = get_kb_item("Host/Solaris/Version");
if ( version && ereg(pattern:"^5\.1[0-9]", string:version)) exit(0);

RPC_PROG = 100221;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 vulnerable = 0;
 os = get_kb_item("Host/OS");
 if(!os)vulnerable = 1;
 else
 {
   if(ereg(pattern:"Solaris (2\.[56]|[7-9])", string:os))vulnerable = 1;
 }

 if(vulnerable)
 {
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
 }
}
