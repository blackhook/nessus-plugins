##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143600);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-8394");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"ManageEngine ServiceDesk Plus < 10.0 Build 10012 Arbitrary File Upload");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by an arbitrary file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"An arbitrary file upload vulnerability exists in ManageEngine ServiceDesk Plus. A low privilege authenticated,
remote attacker can exploit this by uploading arbitrary files to the remote host with the potential to execute
arbitrary code on the server.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/service-desk/readme.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9c2f49f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 10.0 build 10012 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8394");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_keys("installed_sw/manageengine_servicedesk");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('install_func.inc');
include('url_func.inc');
include('http.inc');

var appname = 'manageengine_servicedesk';
var disname = 'ManageEngine ServiceDesk';

get_install_count(app_name:appname, exit_if_zero:TRUE);

var port = get_http_port(default:8080);
var install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
var version = install['version'];
var product = install['Product'];

if ('MSP' >< product)
  audit(AUDIT_INST_VER_NOT_VULN, product);

var build = pregmatch(string:version, pattern:"([0-9\.]+) Build ([0-9]+)");
if(empty_or_null(build)) audit(AUDIT_VER_NOT_GRANULAR, disname, version);

var url = build_url(port:port, qs:install['path']);
var compare_version = build[1] + '.' + build[2];

var report;
if (ver_compare(ver:compare_version, fix:"10.0.10012", strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 10.0 Build 10012' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, disname, url, version);
