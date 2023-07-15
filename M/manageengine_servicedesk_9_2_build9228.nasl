#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94327);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2016-4888", "CVE-2016-4890");
  script_bugtraq_id(93214, 93216);

  script_name(english:"ManageEngine ServiceDesk Plus 9.2.0 < Build 9228 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ManageEngine ServiceDesk Plus.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ManageEngine ServiceDesk Plus version 9.2.0
prior to build 9228. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper validation of input before returning it to
    users. An unauthenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (CVE-2016-4888)

  - An information disclosure vulnerability exists due to
    insecure generation of cookies. An unauthenticated,
    remote attacker can exploit this to disclose password
    information by gaining access to a user's cookie.
    (CVE-2016-4890)

  - An unspecified flaw exists when adding notes for
    'Problems'. An unauthenticated, remote attacker can
    exploit this to cause an unspecified impact.

  - An unspecified flaw exists that is related to scanned
    XML files. An unauthenticated, remote attacker can
    exploit this to cause an unspecified impact.

  - An unspecified flaw exists when trying to delete the
    Change Template. An unauthenticated, remote attacker can
    exploit this to cause an unspecified impact.

  - An unspecified flaw exists when updating or deleting the
    Change workflow. An unauthenticated, remote attacker can
    exploit this to cause an unspecified impact.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/service-desk/readme.html#readme92");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 9.2.0 build 9228 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4890");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_keys("installed_sw/manageengine_servicedesk");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("url_func.inc");
include("http.inc");

var appname = "manageengine_servicedesk";
var disname = "ManageEngine ServiceDesk";

get_install_count(app_name:appname, exit_if_zero:TRUE);

var port = get_http_port(default:8080);
var install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
var product = install['Product'];

if ('MSP' >< product)
  audit(AUDIT_INST_VER_NOT_VULN, product);

var version = install['version'];
var build = pregmatch(string:version, pattern:"([0-9\.]+) Build ([0-9]+)");

if(empty_or_null(build)) audit(AUDIT_VER_NOT_GRANULAR, disname, version);

var url = build_url(port:port, qs:install['path']);
var compare_version = build[1] + '.' + build[2];

var report;
if (ver_compare(ver:compare_version, fix:"9.2.9228", strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 9.2 Build 9228' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, disname, url, version);
