#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175390);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2023-24487", "CVE-2023-24488");
  script_xref(name:"IAVA", value:"2023-A-0243");

  script_name(english:"Citrix ADC and Citrix Gateway Multiple Vulnerabilities (CTX477714)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by multiple vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 12.1 before 12.1-65.35, 13.0 before 13.0-90.11 or 13.1 
before 13.1-45.61. It is therefore affected by multiple vulnerabilities: 

  - A cross-site scripting vulnerability affecting appliances configured as a Gateway (SSL VPN, ICAS Proxy, CVPN, 
    RDP Proxy) or as a AAA Virtual Server. (CVE-2023-24488)

  - An arbitrary file read vulnerability found via access to NSIP or SNIP with management interface access (CVE-2023-24487)

Please refer to advisory CTX477714 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/article/CTX477714/citrix-adc-and-citrix-gateway-security-bulletin-for-cve202324487-cve202324488
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb65364");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 12.1-65.35, 13.0-90.11, 13.1-45.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '12.1', 'fixed_version': '12.1.65.35', 'fixed_display': '12.1-65.35'},
  {'min_version': '13.0', 'fixed_version': '13.0.90.11', 'fixed_display': '13.0-90.11'},
  {'min_version': '13.1', 'fixed_version': '13.1.45.61', 'fixed_display': '13.1-45.61'} 
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  flags:{'xss':TRUE},
  severity:SECURITY_WARNING
);