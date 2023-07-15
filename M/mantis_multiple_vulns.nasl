#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11653);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2002-1110",
    "CVE-2002-1111",
    "CVE-2002-1112",
    "CVE-2002-1113",
    "CVE-2002-1114",
    "CVE-2002-1115",
    "CVE-2002-1116"
  );
  script_bugtraq_id(
    5504,
    5509,
    5510,
    5514,
    5515,
    5563,
    5565
  );

  script_name(english:"Mantis < 0.17.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Mantis on the remote host
contains various flaws that may allow an attacker to execute arbitrary
commands, inject SQL commands, view bugs it should not see, and get a
list of projects that should be hidden.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/272");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/273");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/280");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/282");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/283");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/349");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/351");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 0.17.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(ereg(pattern:"^0\.([0-9]\.|1[0-6]\.|17\.[0-4][^0-9])", string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 0.17.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
