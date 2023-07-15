#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66294);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-2087");
  script_bugtraq_id(59469, 59471);

  script_name(english:"Gallery 3.0.x < 3.0.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Gallery install hosted on the
remote web server is affected by multiple vulnerabilities :

  - The application is affected by an unspecified flaw
    related to stack trace.

  - A cross-site scripting (XSS) vulnerability exists
    because the application fails to validate input passed
    via movie titles. 

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/gallery_3_0_7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 3.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2087");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("gallery_detect.nasl");
  script_require_keys("www/PHP", "www/gallery", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "gallery",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);
version = install["ver"];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Gallery", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 3.0.x < 3.0.5 are vulnerable
if (ver[0] == 3 && ver[1] == 0 && ver[2] < 7)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.0.7\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", install_url, version);
