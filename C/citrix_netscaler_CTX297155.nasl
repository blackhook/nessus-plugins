#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150866);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-8299", "CVE-2020-8300");
  script_xref(name:"IAVA", value:"2021-A-0288-S");

  script_name(english:"Citrix ADC and Citrix NetScaler Gateway Multiple Vulnerabilities (CTX297155)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix NetScaler Gateway device is version 11.1.x prior to 11.1.65.20, 12.1.x prior to 
12.1.62.23 or 13.0.x prior to 13.0.82.41. It is, therefore, affected by multiple vulnerabilities:

  - Network-based denial-of-service from within the same Layer 2 network segment (CVE-2020-8299)

  - SAML authentication hijack through a phishing attack to steal a valid user session (CVE-2020-8300)

Please refer to advisory CTX297155 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX297155");
  script_set_attribute(attribute:"solution", value:
"For versions 11.1.x, 12.1.x and 13.0.x, upgrade to 11.1.65.20, 12.1.62.23 and 13.0.82.41, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '11.1', 'fixed_version': '11.1.65.20', 'fixed_display':'11.1-65.20'},
  {'min_version': '12.1', 'fixed_version': '12.1.62.23', 'fixed_display':'12.1-62.23'},
  {'min_version': '13.0', 'fixed_version': '13.0.82.41', 'fixed_display':'13.0-82.41'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);