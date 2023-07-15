#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137367);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/15");

  script_cve_id(
    "CVE-2020-9643",
    "CVE-2020-9644",
    "CVE-2020-9645",
    "CVE-2020-9647",
    "CVE-2020-9648",
    "CVE-2020-9651"
  );
  script_xref(name:"IAVA", value:"2020-A-0253-S");

  script_name(english:"Adobe Experience Manager 6.1.x < 6.4.8.1 / 6.5.x < 6.5.5.0 (APSB20-31)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager installed on the remote host is affected by multiple vulnerabilities (APSB20-31)");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is 6.1.x, 6.2.x, 6.3.x, 6.4.x prior to 6.4.8.1, 
or 6.5.x prior to 6.5.5.0. It is, therefore, affected by multiple vulnerabilities:

  - An unspecified server-side request forgery (SSRF) that
    could result in sensitive information disclosure 
    (CVE-2020-9643)

  - An unspecified cross-site scripting vulnerability that
    could result in arbitrary javaScript execution 
    (CVE-2020-9644, CVE-2020-9647, CVE-2020-9648, CVE-2020-9651)

  - An unspecified blind server-side request forgery that
    could result sensitive information disclosure 
    (CVE-2020-9645)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number. To retrieve patch level information, this plugin requires the HTTP credentials of the web console. For accurate
results, you may need to enable the Adobe Experience Manager ports (by default, 4502 and/or 4503) in your Nessus
scan.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb20-31.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22dc4755");
  script_set_attribute(attribute:"solution", value:
"Apply the recommended update from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.1', 'fixed_version' : '6.4.8.1'},
  { 'min_version' : '6.5', 'fixed_version' : '6.5.5.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

