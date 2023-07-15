#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167195);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2022-27510", "CVE-2022-27513", "CVE-2022-27516");
  script_xref(name:"IAVA", value:"2022-A-0465-S");

  script_name(english:"Citrix ADC and Citrix Gateway 12.1.x < 12.1-65.21 / 13.0.x < 13.0-88.12 / 13.1.x < 13.1-33.47 Multiple Vulnerabilities (CTX463706)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 12.1.x prior to 12.1-65.21, 13.0.x prior to 13.0-88.12 or
13.1.x prior to 13.1-33.47. It may, therefore, be affected by multiple vulnerabilities, as follows:

  - User login brute force protection functionality bypass. (CVE-2022-27516)

  - Remote desktop takeover via phishing. (CVE-2022-27513)

  - Unauthorized access to Gateway user capabilities. (CVE-2022-27510)

Please refer to advisory CTX463706 for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX463706");
  script_set_attribute(attribute:"solution", value:
"For versions 12.1.x, 13.0.x and 13.1.x, upgrade to 12.1-65.21, 13.0-88.12 and 13.1-33.47, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27510");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-27516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '12.1', 'fixed_version': '12.1.65.21', 'fixed_display':'12.1-65.21'},
  {'min_version': '13.0', 'fixed_version': '13.0.88.12', 'fixed_display':'13.0-88.12'},
  {'min_version': '13.1', 'fixed_version': '13.1.33.47', 'fixed_display':'13.1-33.47'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
