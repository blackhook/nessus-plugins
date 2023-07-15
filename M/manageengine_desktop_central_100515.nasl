#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135186);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/07");

  script_cve_id("CVE-2020-8509");
  script_xref(name:"IAVA", value:"2020-A-0122-S");

  script_name(english:"ManageEngine Desktop Central < 10 Build 10.0.515 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote host is prior to version 10 build 10.0.515. It is,
therefore, affected by an information disclosure vulnerability in the PDFGenerationServlet component due to improper
access controls. An unauthenticated, remote attacker can exploit this to disclose potentially sensitive information.");
  # https://www.manageengine.com/products/desktop-central/unauthenticated-servlet-access.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70529b7a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central version 10 build 10.0.515 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central");
  script_require_ports("Services/www", 8020, 8383, 8040);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('webapp_func.inc');

appname = 'ManageEngine Desktop Central';
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8020);

install = get_single_install(
  app_name            : appname,
  port                : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
build   = install['build'];
ismsp   = install['MSP'];
rep_version = version;

install_url =  build_url(port:port, qs:dir);

if (ismsp) appname += ' MSP';

if (build == UNKNOWN_VER)
  exit(0, 'The build number of '+appname+' version ' +rep_version+ ' listening at ' +install_url+ ' could not be determined.');
else
  rep_version += ' Build ' + build;

build = int(build);
if (version =~ "^10(\.|$)" && build < 100515)
{
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 10 Build 100515' +
      '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
