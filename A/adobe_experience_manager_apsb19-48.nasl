#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139204);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2019-8078",
    "CVE-2019-8079",
    "CVE-2019-8080",
    "CVE-2019-8081",
    "CVE-2019-8082",
    "CVE-2019-8083",
    "CVE-2019-8084",
    "CVE-2019-8085",
    "CVE-2019-8086",
    "CVE-2019-8087",
    "CVE-2019-8088",
    "CVE-2019-8234"
  );
  script_xref(name:"IAVB", value:"2019-B-0080-S");

  script_name(english:"Adobe Experience Manager 6.x < 6.3.3.6 / 6.4.x < 6.4.6.0 / 6.5.x < 6.5.2.0 Multiple Vulnerabilities (APSB19-48)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is 6.x prior to 6.3.3.6, 6.4.x prior to 6.4.6.0,
or 6.5.x prior to 6.5.2.0. It is, therefore, affected by multiple vulnerabilities :

  - Adobe Experience Manager versions 6.5, 6.4, 6.3 and 6.2 have a command injection vulnerability. Successful
    exploitation could lead to arbitrary code execution. (CVE-2019-8088)

  - Adobe Experience Manager versions 6.5, 6.4, 6.3 and 6.2 have an authentication bypass vulnerability.
    Successful exploitation could lead to sensitive information disclosure. (CVE-2019-8081)

  - Adobe Experience Manager versions 6.4, 6.3 and 6.2 have a xml external entity injection vulnerability.
    Successful exploitation could lead to sensitive information disclosure. (CVE-2019-8082)

It is also affected by additional vulnerabilities, including cross-site scripting (XSS), cross-site request forgery
(XSRF), and additional xml external entity injection vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number. To retrieve patch level information, this plugin requires the HTTP credentials of the web console. For accurate
results, you may need to enable the Adobe Experience Manager ports (by default, 4502 and/or 4503) in your Nessus
scan.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb20-15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7263dec");
  script_set_attribute(attribute:"solution", value:
"Apply the recommended update from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

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

app_info = vcf::get_app_info(app:'Adobe Experience Manager', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '6.0', 'fixed_version' : '6.3.3.6'},
  { 'min_version' : '6.4', 'fixed_version' : '6.4.6.0'},
  { 'min_version' : '6.5', 'fixed_version' : '6.5.2.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{ xss:TRUE, xsrf:TRUE }
);
