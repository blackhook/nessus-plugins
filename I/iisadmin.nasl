#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10358);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-1538");
  script_bugtraq_id(189);

  script_name(english:"Microsoft IIS /iisadmin Unrestricted Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"When Microsoft Internet Information Server (IIS) 4.0 is upgraded from
version 2.0 or 3.0 the ism.dll file is left in the /scripts/iisadmin
directory. This script discloses sensitive information via a specially
crafted URL which could lead to elevated privileges. An attacker could
use this to gain access to the administrator's password.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=91638375309890&w=2");
  script_set_attribute(attribute:"solution", value:
"Restrict access to /iisadmin through the IIS ISM.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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

banner = get_http_banner(port:port);
if ( ! banner || "Microsoft-IIS/" >!< banner ) exit(0);
if ( ! get_port_state(port) ) exit(0);

res = http_send_recv3(method:"GET", item:"/iisadmin/", port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
if ( ereg(pattern:"HTTP/[01]\.[01] 200 ", string:res[2]) &&
     "<TITLE>IIS Internet Services Manager (HTMLA)</TITLE>" >< res[2] ) security_note(port);
