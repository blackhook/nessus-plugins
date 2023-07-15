#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133695);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id("CVE-2020-3741");

  script_name(english:"Adobe Experience Manager 6.4 and 6.5 DoS (APSB20-08)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is 6.4 or 6.5 without hotfixes
cq-6.4.0-hotfix-31868 or cq-6.5.0-hotfix-31870. It is, therefore, affected by an uncontrolled resource consumption
vulnerability which, if successfully exploited, leads to a denial-of-service (DoS) condition.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number. To retrieve patch level information this plugin requires the HTTP credentials of the web console. For accurate
results, you may need to enable the Adobe Experience Manager ports (by default, 4502 and/or 4503) in your Nessus
scan.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb20-08.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5df070a1");
  script_set_attribute(attribute:"solution", value:
"Apply the recommended update from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
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

if ('cq-6.4.0-hotfix-31868' >< app_info['Hotfixes'] || 'cq-6.5.0-hotfix-31870' >< app_info['Hotfixes'])
  audit(AUDIT_HOST_NOT, 'affected');

constraints = [
  {
    'min_version'   : '6.4',
    'fixed_version' : '6.4.999',
    'fixed_display' : 'cq-6.4.0-hotfix-31868 (Package Share) / cq-6.4.0-hotfix-31868-1.0 (Software Distribution)'
  },
  {
    'min_version'   : '6.5',
    'fixed_version' : '6.5.999',
    'fixed_display' : 'cq-6.5.0-hotfix-31870 (Package Share) / cq-6.5.0-hotfix-31870-1.0 (Software Distribution)'
  }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
