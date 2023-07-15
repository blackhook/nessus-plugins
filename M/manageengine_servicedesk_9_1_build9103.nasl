#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85599);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");


  script_name(english:"ManageEngine ServiceDesk Plus 9.1.0 < Build 9103 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ManageEngine ServiceDesk Plus.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ManageEngine ServiceDesk Plus version 9.1.0
prior to build 9103. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input on the
    'Login' page. A remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code.

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when adding
    new software license types or options. A remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code.

  - An unspecified flaw exists in the file attachment URL
    on the software details page.

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when sending
    reports by email. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code.

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    'module' and 'from' parameters when completing the 'Add
    new task' action. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code.

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    'UNIQUE_ID' parameter in the 'Solution' module. A remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code.

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the email
    notification window. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code.

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    request template, reminder, and technician calendar. A
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code.

  - A security bypass vulnerability exists due to an
    unspecified flaw. An authenticated, remote attacker can
    exploit this to update incident details.

  - A security bypass vulnerability exists due to an
    unspecified flaw. An authenticated, remote attacker can
    exploit this to access problem and change details.

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code.

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input before using it in
    SQL queries. A remote attacker can exploit this to
    inject or manipulate SQL queries, resulting in the
    manipulation or disclosure of arbitrary data.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/service-desk/readme.html#readme91");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 9.1.0 build 9103 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/manageengine_servicedesk");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");
include("url_func.inc");

var appname = "manageengine_servicedesk";
var disname = "ManageEngine ServiceDesk";

get_install_count(app_name:appname, exit_if_zero:TRUE);

var port    = get_http_port(default:8080);
var install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
var product = install['Product'];

if ('MSP' >< product)
  audit(AUDIT_INST_VER_NOT_VULN, product);

var version = install['version'];
var url     = build_url(port:port, qs:install['path']);
var build   = pregmatch(string:version, pattern:"[B|b]uild ([0-9]+)");

if(empty_or_null(build))
  audit(AUDIT_VER_NOT_GRANULAR, disname, version);
build   = int(build[1]);

var report;
if(version =~ "^9\.1(\.| )" && build < 9103)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 9.1 Build 9103' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xss:TRUE, sqli:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, disname, url, version);
