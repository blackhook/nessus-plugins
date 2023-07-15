#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168654);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/16");

  script_cve_id("CVE-2022-27518");
  script_xref(name:"CEA-ID", value:"CEA-2022-0039");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/03");
  script_xref(name:"IAVA", value:"2022-A-0520");

  script_name(english:"Citrix ADC and Citrix Gateway RCE (CTX474995)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 12.1 before 12.1-65.25 or 13.0 before 13.0-58.32. It is 
therefore affected by an unauthentictaed remote code execution vulnerability: 

  - A vulnerability has been discovered in Citrix ADC (formerly known as NetScaler ADC) and Citrix Gateway (formerly 
    known as NetScaler Gateway). Unauthenticated remote arbitrary code execution exists if either Citrix ADC or Citrix 
    Gateway are configured as a SAML SP or a SAML IdP  (CVE-2022-27518)

Please refer to advisory CTX474995 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/article/CTX474995/citrix-adc-and-citrix-gateway-security-bulletin-for-cve202227518
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eddc75c1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 12.1-65.25, 13.0-58.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27518");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '12.1', 'fixed_version': '12.1.65.25', 'fixed_display': '12.1-65.25'},
  {'min_version': '13.0', 'fixed_version': '13.0.58.32', 'fixed_display': '13.0-58.32'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
