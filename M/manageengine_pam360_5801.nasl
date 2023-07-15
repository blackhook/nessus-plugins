#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169605);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id("CVE-2022-47523");
  script_xref(name:"CEA-ID", value:"CEA-2023-0001");
  script_xref(name:"IAVA", value:"2023-A-0017");

  script_name(english:"ManageEngine PAM360 < 5.8 Build 5801 SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine PAM360 prior to 5.8 Build 5801. It is, therefore, affected by a
SQL injection vulnerability. An unauthenticated, remote attacker can exploit this to inject or manipulate SQL queries in
the back-end database, resulting in the disclosure or manipulation of arbitrary data.

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://www.manageengine.com/privileged-session-management/advisory/cve-2022-47523.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?178d8a0c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine PAM360 version 5.8 Build 5801 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-47523");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_pam360");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_pam360_detect.nbin");
  script_require_keys("installed_sw/ManageEngine PAM360");
  script_require_ports("Services/www", 8282);

  exit(0);
}

include('vcf_extras_zoho.inc');
include('http.inc');

var appname = 'ManageEngine PAM360';
var port    = get_http_port(default:8282, embedded:TRUE);

var app_info = vcf::zoho::fix_parse::get_app_info(app:appname, port:port);

var constraints = [
  { 'max_version' : '5800', 'fixed_version' : '5801', 'fixed_display' : '5.8 Build 5801' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);

