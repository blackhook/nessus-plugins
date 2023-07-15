#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# From: "JvdR" <thewarlock@home.nl>
# To: <bugtraq@securityfocus.com>
# Subject: Multiple Vulnerabilities in Invision Power Board v1.3.1 Final.
# Date: Tue, 8 Jun 2004 16:53:11 +0200
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12268);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(10511);

  script_name(english:"Invision Power Board ssi.php f Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the version of Invision Power Board on the
remote host such that unauthorized users can inject SQL commands
through the 'ssi.php' script.  An attacker may use this flaw to gain
the control of the remote database.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Jun/124");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:invisionpower:invision_power_board");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_require_keys("www/invision_power_board");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  w = http_send_recv3(method:"GET", item:string(dir, "/ssi.php?a=out&type=xml&f=0)'"), port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  if ( "AND t.approved=1 ORDER BY t.last_post" >< res )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
