#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10681);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0960");
  script_bugtraq_id(1787);

  script_name(english:"Netscape Messenging Server POP3 Error Message User Account Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"The remote POP server allows an attacker to determine whether
a given username exists or not.");
  script_set_attribute(attribute:"description", value:
"The remote POP server allows an attacker to obtain a list
of valid logins on the remote host, thanks to a brute-force
attack.

If the user connects to this port and issues the commands :
USER 'someusername'
PASS 'whatever'

the user will then get a different response whether the account
'someusername' exists or not.");
  script_set_attribute(attribute:"solution", value:
"None at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netscape:messaging_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/pop3", 110);

  exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("pop3_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner =  get_pop3_banner(port:port);
if ( ! banner || "Netscape Messaging Server" >!< banner ) exit(0);

if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(r)
  {
   send(socket:soc, data:string("USER nessus", rand(), "\r\n"));
   r = recv_line(socket:soc, length:4096);
   send(socket:soc, data:string("PASS nessus", rand(), "\r\n"));
   r = recv_line(socket:soc, length:4096);
   close(soc);
   if(r && "User unknown" >< r)security_warning(port);
  }
 }
}
