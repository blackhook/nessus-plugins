#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93197);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"DNN (DotNetNuke) < 8.0.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of DNN Platform (formerly DotNetNuke) running on the
remote host is affected by multiple vulnerabilities :

  - A flaw exists due to improper validation of user
    permissions. An authenticated, remote attacker with
    permissions to edit a particular page can exploit this
    to make changes to site containers across all pages.

  - A cross-site redirection vulnerability exists due to
    improper validation of links to the registration page
    before returning it to the user. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to follow a crafted link, to redirect the user to a
    malicious website

  - An unspecified flaw exists that allows an authenticated,
    remote attacker with access to files outside of the root
    of the DNN site, to copy an existing image to any
    location on the server.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dnnsoftware.com/community/security/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN Platform version 8.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];

install_url = build_url(qs:dir, port:port);

fixed_version = '8.0.4';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
