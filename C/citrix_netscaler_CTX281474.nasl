#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140790);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2020-8245", "CVE-2020-8246", "CVE-2020-8247");
  script_xref(name:"IAVA", value:"2020-A-0434-S");

  script_name(english:"Citrix ADC and Citrix NetScaler Gateway Multiple Vulnerabilities (CTX281474)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix NetScaler Gateway device is version 11.1.x prior to 11.1.65.12, 12.1.x prior to 
12.1.58.15 or 13.0.x prior to 13.0.64.35. It is, therefore, affected by multiple vulnerabilities:
  - A HTML injection vulnerability exists in Citrix ADC due to improper validation of user-supplied input. 
  An unauthenticated, remote attacker can exploit this to inject arbitrary content into responses generated
  by the application (CVE-2020-8245).

  - A denial of service (DoS) vulnerability exists in Citrix ADC. An unauthenticated, remote attacker can 
  exploit this issue, to impose a DoS condition on the application (CVE-2020-8246).

  - A privilege escalation vulnerability exists in management interface component. An authenticated, 
  remote attacker can exploit this, to gain privileged access to the system (CVE-2020-8247). 

Please refer to advisory CTX281474 for more information.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX281474");
  script_set_attribute(attribute:"solution", value:
"For versions 11.1.x, 12.1.x and 13.0.x, upgrade to 11.1.65.12, 12.1.58.15 and 13.0.64.35, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}
include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '11.1', 'fixed_version': '11.1.65.12', 'fixed_display': '11.1-65.12'},
  {'min_version': '12.1', 'fixed_version': '12.1.58.15', 'fixed_display': '12.1-58.15'},
  {'min_version': '13.0', 'fixed_version': '13.0.64.35', 'fixed_display': '13.0-64.35'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
