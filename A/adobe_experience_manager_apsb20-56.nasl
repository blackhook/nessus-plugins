#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140531);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id(
    "CVE-2020-9733",
    "CVE-2020-9735",
    "CVE-2020-9736",
    "CVE-2020-9737",
    "CVE-2020-9738",
    "CVE-2020-9740",
    "CVE-2020-9742",
    "CVE-2020-9743"
  );
  script_xref(name:"IAVA", value:"2020-A-0422-S");

  script_name(english:"Adobe Experience Manager 6.2.x <= 6.2 SP1-CFP20 / 6.3.x <= 6.3.3.8 / 6.4.x < 6.4.8.2 / 6.5.x < 6.5.6.0 (APSB20-56)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager installed on the remote host is affected by multiple vulnerabilities (APSB20-56)");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is 6.2.x through 6.2 SP1-SFP20, 6.3.x through
6.3.3.8, 6.4.x prior to 6.4.8.2, or 6.5.x prior to 6.5.6.0. It is, therefore, affected by multiple vulnerabilities:

  - Adobe Experience Manager executes with unnecessary privileges, which allows an attacker to cause sensitive
    information disclosure. (CVE-2020-9733)

  - A stored cross-site scripting vulnerability exists in Adobe Experience Manager that allows an attacker to
    execute arbitrary code in a user's browser. (CVE-2020-9735, CVE-2020-9736, CVE-2020-9737, CVE-2020-9738,
    CVE-2020-9740)

  - A reflected cross-site scripting vulnerability exists in Adobe Experience Manager that allows an attacker
    to execute arbitrary code in a user's browser. (CVE-2020-9742)

  - An HTML injection vulnerability exists that allows an attacker to cause inject arbitrary HTML in a user's
    browser. (CVE-2020-9743)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number. To retrieve patch level information, this plugin requires the HTTP credentials of the web console. For accurate
results, you may need to enable the Adobe Experience Manager ports (by default, 4502 and/or 4503) in your Nessus
scan.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb20-56.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d245226a");
  script_set_attribute(attribute:"solution", value:
"Apply the recommended update from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");
  script_require_ports("Services/www", 4502, 4503);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:4502);

app = 'Adobe Experience Manager';

app_info = vcf::get_app_info(app:app, port:port);

# We don't have granular versioning for 6.2 yet
if (report_paranoia < 2 && app_info.version =~ "^6\.2") audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '6.2', 'max_version' :   '6.3.3.8',  'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.4', 'fixed_version' : '6.4.8.2'},
  { 'min_version' : '6.5', 'fixed_version' : '6.5.6.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);

