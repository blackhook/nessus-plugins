#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12297);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-0679");
  script_bugtraq_id(10663);

  script_name(english:"UnrealIRCd IP Cloaking Weakness Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running an IRC server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running UnrealIRCd, a popular IRC server.

The remote version of this server offers an 'IP cloaking' 
capability that offers to hide the IP address of the users 
connected to the server in order to preserve their anonymity.

There is a design error in the algorithm used by the server 
that could allow an attacker to guess the real IP address of 
another user of the server by reducing the number of tries to 
2,000.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to UnrealIRCd 3.2.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:unrealircd:unrealircd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
  script_require_ports("Services/irc", 6667);

  exit(0);
}

#

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

# Unreal ircd
if(egrep(pattern:".*Unreal3\.(0\.|1\.[01][^0-9])", string:banner))
{
 security_warning(port);
 exit(0);
}

