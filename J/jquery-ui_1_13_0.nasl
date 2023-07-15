#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156443);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/09");

  script_cve_id("CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184");
  script_xref(name:"IAVB", value:"2021-B-0071-S");

  script_name(english:"JQuery UI < 1.13.0 Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of JQuery UI library hosted on the remote web server is prior to 1.13.0. It is, therefore, affected by
multiple cross-site scripting vulnerabilities:

  - Accepting the value of the 'altField' option of the Datepicker widget from untrusted sources may execute untrusted
    code. (CVE-2021-41182)

  - Accepting the value of various '*Text' options of the Datepicker widget from untrusted sources may execute
    untrusted code. (CVE-2021-41183)

  - Accepting the value of the 'of' option of the '.position()' util from untrusted sources may execute untrusted
    code. (CVE-2021-41184)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JQuery UI version 1.13.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jquery_ui_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/jquery_ui");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var appname = 'jquery ui';

get_install_count(app_name:appname, exit_if_zero:TRUE);

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

var constraints = [{'fixed_version':'1.13.0'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
