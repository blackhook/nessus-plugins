#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155584);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/09");

  script_cve_id("CVE-2021-22955", "CVE-2021-22956");
  script_xref(name:"IAVA", value:"2021-A-0553");

  script_name(english:"Citrix ADC and Citrix NetScaler Gateway Multiple Vulnerabilities (CTX330728)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix NetScaler Gateway device is version 11.1.x prior to 11.1.65.23, 12.1.x prior to 
12.1.63.22, 13.0.x prior to 13.0.83.27, or 13.1.x prior to 13.1.4.43. It is, therefore, affected by multiple
vulnerabilities:

  - Unauthenticated denial of service (CVE-2021-22955)

  - Temporary disruption of the Management GUI, Nitro API and RPC communication (CVE-2021-22956)

Please refer to advisory CTX330728 for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX330728");
  script_set_attribute(attribute:"solution", value:
"For versions 11.1.x, 12.1.x, 13.0.x, and 13.1.x, upgrade to 11.1.65.23, 12.1.63.22, 13.0.83.27, and 13.1.4.43, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '11.1', 'fixed_version': '11.1.65.23', 'fixed_display':'11.1-65.23'},
  {'min_version': '12.1', 'fixed_version': '12.1.63.22', 'fixed_display':'12.1-63.22'},
  {'min_version': '13.0', 'fixed_version': '13.0.83.27', 'fixed_display':'13.0-83.27'},
  {'min_version': '13.1', 'fixed_version': '13.1.4.43',  'fixed_display':'13.1-4.43'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
