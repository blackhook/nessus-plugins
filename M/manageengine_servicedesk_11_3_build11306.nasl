#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155864);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-44077");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");

  script_name(english:"ManageEngine ServiceDesk Plus < 11.3 Build 11306 / ManageEngine ServiceDesk Plus MSP < 10.5 Build 10530 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in ManageEngine ServiceDesk Plus prior to 11.3 Build 11306 and
ManageEngine ServiceDesk Plus MSP prior to 10.5 Build 10530 due to a flaw in the /RestAPI URLs in a servlet and
ImportTechnicians in the Struts configuration.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://www.manageengine.com/products/service-desk/on-premises/readme.html#11306
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?088fc18e");
  # https://www.manageengine.com/products/service-desk-msp/readme.html#10530
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2d78a24");
  # https://pitstop.manageengine.com/portal/en/community/topic/security-advisory-authentication-bypass-vulnerability-in-servicedesk-plus-msp-versions-10527-and-above-16-9-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33ec753b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 11.3 build 11306 or ManageEngine ServiceDesk Plus MSP version 10.5
Build 10530, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44077");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine ServiceDesk Plus CVE-2021-44077');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_servicedesk_plus");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_servicedesk_plus_msp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var build = pregmatch(string:version, pattern:"([0-9\.]+) Build ([0-9]+)");
if(empty_or_null(build)) audit(AUDIT_VER_NOT_GRANULAR, display_name, version);

var url = build_url(port:port, qs:install['path']);
var compare_version = build[1] + '.' + build[2];

var fix_ver = '11.3.11306';
var fix_display = '11.3 Build 11306';
if ('MSP' >< product)
{
  var fix_ver = '10.5.10530';
  var fix_display = '10.5 Build 10530';
}

if (ver_compare(ver:compare_version, fix:fix_ver, strict:FALSE) < 0)
{
  var report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_display +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, display_name, url, version);
