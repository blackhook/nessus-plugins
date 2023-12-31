#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82081);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-7862");
  script_bugtraq_id(71849);

  script_name(english:"ManageEngine Desktop Central Remote Security Bypass");
  script_summary(english:"Checks the version of ManageEngine Desktop Central.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that is affected
by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central running on the remote host
is affected by a remote security bypass vulnerability, due to a
failure to restrict access to 'DCPluginServelet'. This allows an
unauthenticated, remote attacker to create an account with full
administrative privileges within DesktopCentral and then perform any
tasks DesktopCentral administrative users could perform, including the
execution of code and commands on systems managed by DesktopCentral.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2015/Jan/2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 9 build 90109 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central");
  script_require_ports("Services/www", 8020, 8383, 8040);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "ManageEngine Desktop Central";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8020);

install = get_single_install(
  app_name            : appname,
  port                : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];
build   = install["build"];
ismsp   = install["MSP"];
rep_version = version;
if(build !=  UNKNOWN_VER)
  rep_version += " Build "+build;
install_url =  build_url(port:port, qs:dir);

# 7 - 9 build 90109
if (version !~ "^[7-9](\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);

if (version =~ "^9(\.|$)" && build == UNKNOWN_VER)
  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");

if (int(build) < 90109)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 9 Build 90109' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
