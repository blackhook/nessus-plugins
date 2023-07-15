##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144017);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-24444", "CVE-2020-24445");
  script_xref(name:"IAVA", value:"2020-A-0568-S");

  script_name(english:"Adobe Experience Manager 6.2 <= 6.2 SP1-CFP20 / 6.3 <= 6.3.3.8 / 6.4 < 6.4.8.3 / 6.5 < 6.5.7.0 Multiple Vulnerabilities (APSB20-01)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is affected by multiple vulnerabilities as referenced in the APSB20-72 advisory, as follows:

  - AEM's Cloud Service offering, as well as versions 6.5.6.0 (and below), 6.4.8.2 (and below) and 6.3.3.8 (and below)
    are affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by an attacker to inject
    malicious scripts into vulnerable form fields. Malicious JavaScript may be executed in a victim’s browser when
    they browse to the page containing the vulnerable field. (CVE-2020-24445)

  - AEM Forms SP6 add-on for AEM 6.5.6.0 and Forms add-on package for AEM 6.4 Service Pack 8 Cumulative Fix Pack 2
    (6.4.8.2) have a blind Server-Side Request Forgery (SSRF) vulnerability. This vulnerability could be exploited by an
    unauthenticated attacker to gather information about internal systems that reside on the same network.
    (CVE-2020-24444)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb20-72.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28120d09");
  script_set_attribute(attribute:"solution", value:
"Apply the recommended update from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24444");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-24445");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");

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
  { 'min_version' : '6.4', 'fixed_version' : '6.4.8.3'},
  { 'min_version' : '6.5', 'fixed_version' : '6.5.7.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
