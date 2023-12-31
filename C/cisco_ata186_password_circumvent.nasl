#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11012);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0769");
  script_bugtraq_id(4711, 4712);

  script_name(english:"Cisco ATA-186 Password Circumvention / Recovery");

  script_set_attribute(attribute:"synopsis", value:
"The remote telephone adapter has a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Cisco ATA-186 - an analog telephone
adapter used to interface analog telephones to VoIP networks.

The adapter is configured via a web interface that has a security
bypass vulnerability.  It is possible to bypass authentication by
sending an HTTP POST request with a single byte, which could allow
a remote attacker to take control of the device.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/May/92");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20040329-ata-password-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97d3ed5d");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:ata-186");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


if (! get_port_state(port))exit(0);


r = http_send_recv3( port: port, item:"/dev/", method: "GET",	
      		     username: "", password: "" );
if (isnull(r)) exit(0);
if (r[0] !~ "^HTTP[0-9]\.[0-9] 403 ") exit(0);

r = http_send_recv3( port: port, item:"/dev/", method: "POST",
    		     username: "", password: "", data: "a");
if (r =~ "^HTTP[0-9]\.[0-9] 200 ") security_hole(port);



