#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10151);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-1475");
  script_bugtraq_id(7538);

  script_name(english:"NetBus 1.x Software Detection");

  script_set_attribute(attribute:"synopsis", value:
"A potentially malicious remote administration service is detected.");
  script_set_attribute(attribute:"description", value:
"NetBus 1.x is installed.

NetBus is a remote administration tool that can be used for malicious
purposes, such as sniffing what the user is typing, its passwords and
so on. 

An attacker may have installed it to control hosts on your network. 

Furthermore, Netbus authentication may be bypassed.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/320980");
  script_set_attribute(attribute:"solution", value:
"Netbus should be removed from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netbus:netbus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 1999-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports(12345, "Services/netbus");

  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/netbus");
if(!port)port = 12345;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {

#
# Anti-deception toolkit check
#
  r = recv(socket:soc, length:1024);
  close(soc);
  if("NetBus" >< r){
  	security_hole(port);
	}
  }
}
