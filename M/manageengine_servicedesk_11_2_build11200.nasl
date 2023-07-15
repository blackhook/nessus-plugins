##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148429);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2021-20080");

  script_name(english:"ManageEngine ServiceDesk Plus < 11.2 Build 11200 Unauthenticated Stored XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"A stored cross-site scripting (XSS) vulnerability exists in the XML processing logic of asset discovery. By sending a 
crafted HTTP POST request to /discoveryServlet/WsDiscoveryServlet, a remote, unauthenticated attacker can create an
asset containing malicious JavaScript. When an administrator views this asset, the JavaScript will execute. This can be
exploited to perform authenticated application actions on behalf of the administrator user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://www.manageengine.com/products/service-desk/on-premises/readme.html#readme112
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?984da634");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 11.2 build 11200 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20080");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_keys("installed_sw/manageengine_servicedesk");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('install_func.inc');
include('url_func.inc');
include('http.inc');

var appname = 'manageengine_servicedesk';
var display_name = 'ManageEngine ServiceDesk';

get_install_count(app_name:appname, exit_if_zero:TRUE);
var port = get_http_port(default:8080);

var install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

var version = install['version'];
var product = install['Product'];

if ('MSP' >< product)
  audit(AUDIT_INST_VER_NOT_VULN, product);
  
var build = pregmatch(string:version, pattern:"([0-9\.]+) Build ([0-9]+)");
if(empty_or_null(build)) audit(AUDIT_VER_NOT_GRANULAR, display_name, version);

var url = build_url(port:port, qs:install['path']);
var compare_version = build[1] + '.' + build[2];
if (ver_compare(ver:compare_version, fix:"11.2.11200", strict:FALSE) < 0)
{
  var report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 11.2 Build 11200' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, display_name, url, version);
