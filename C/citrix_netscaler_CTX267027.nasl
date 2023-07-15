##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(132397);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id("CVE-2019-19781");
  script_xref(name:"IAVA", value:"2020-A-0001-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0122");
  script_xref(name:"CEA-ID", value:"CEA-2019-0742");

  script_name(english:"Citrix ADC and Citrix NetScaler Gateway Arbitrary Code Execution (CTX267027)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix NetScaler Gateway device is affected by an arbitrary code execution vulnerability.
An unauthenticated, remote attacker may be able to leverage this vulnerability to perform arbitrary code execution on 
an affected host.

Please refer to advisory CTX267027 for more information.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX267027");
  script_set_attribute(attribute:"solution", value:
"For versions 10.5.x, 11.1.x, 12.0.x, 12.1.x and 13.0.x, upgrade to 10.5.70.12, 11.1.63.15, 12.0.63.13, 12.1.55.18 and 
13.0.47.24 respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19781");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Citrix ADC (NetScaler) Directory Traversal RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_access_gateway_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}
include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '10.5', 'fixed_version': '10.5.70.12', 'fixed_display': '10.5-70.12'},
  {'min_version': '11.1', 'fixed_version': '11.1.63.15', 'fixed_display': '11.1-63.15'},
  {'min_version': '12.0', 'fixed_version': '12.0.63.13', 'fixed_display': '12.0-63.13'},
  {'min_version': '12.1', 'fixed_version': '12.1.55.18', 'fixed_display': '12.1-55.18'},
  {'min_version': '13.0', 'fixed_version': '13.0.47.24', 'fixed_display': '13.0-47.24'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity:SECURITY_HOLE
);
