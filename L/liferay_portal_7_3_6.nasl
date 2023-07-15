#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151292);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/26");

  script_cve_id("CVE-2021-29043", "CVE-2021-29044");
  script_xref(name:"IAVA", value:"2021-A-0296-S");

  script_name(english:"Liferay Portal 7.x <= 7.2.1 / 7.3 < 7.3.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Liferay Portal 7.x through 7.2.1 and 7.3.x before 7.3.6 is affected by multiple vulnerabilities, as follows:

  - The Portal Store module in Liferay Portal 7.0.0 through 7.3.5, and Liferay DXP 7.0 before fix pack 97, 7.1
    before fix pack 21, 7.2 before fix pack 10 and 7.3 before fix pack 1 does not obfuscate the S3 store's
    proxy password, which allows attackers to steal the proxy password via man-in-the-middle attacks or
    shoulder surfing. (CVE-2021-29043)

  - Cross-site scripting (XSS) vulnerability in the Site module's membership request administration pages in
    Liferay Portal 7.0.0 through 7.3.5, and Liferay DXP 7.0 before fix pack 97, 7.1 before fix pack 21, 7.2
    before fix pack 10 and 7.3 before fix pack 1 allows remote attackers to inject arbitrary web script or
    HTML via the _com_liferay_site_my_sites_web_portlet_MySitesPortlet_comments parameter. (CVE-2021-29044)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/120743548
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7571afb");
  # https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/120743515
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b297f97d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 7.3 CE GA7 (7.3.6) or 7.2 GA2 (7.2.1) and apply the latest patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("installed_sw/liferay_portal");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'liferay_portal';
var port = get_http_port(default:8080);

var app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

# Not checking for patches on 7.0-7.2, so require paranoia
if (app_info.version =~ "^7\.([01]|2\.[01])($|[^0-9])" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Liferay Portal', app_info.version);

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.2.2', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.3', 'fixed_version' : '7.3.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
