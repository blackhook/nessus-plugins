#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72966);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-7285");
  script_bugtraq_id(64760);

  script_name(english:"Artifactory < 3.1.1.1 XStream Remote Code Execution");
  script_summary(english:"Checks version of Artifactory");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application uses a library with a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of Artifactory prior to 3.1.1.1 is hosted on the remote web
server.  As such, it uses a library that has a known remote code
execution vulnerability.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Artifactory 3.1.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-7285");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jfrog:artifactory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("artifactory_detect.nbin");
  script_require_keys("www/Artifactory");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Artifactory";
fixed = "3.1.1.1";

port = get_http_port(default:8081);

install = get_install_from_kb(appname:app, port:port, exit_on_fail:TRUE);

version = install["ver"];
path = install["dir"];

if (ver_compare(ver:version, fix:fixed, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, path, version);

if (report_verbosity > 0)
{
  report =
  '\n  URL               : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fixed +
  '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
