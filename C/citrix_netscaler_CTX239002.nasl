##
# (C) Tenable Network Security, Inc.
##
include('compat.inc');

if (description)
{
  script_id(118463);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2018-18517");
  script_bugtraq_id(105725);
  script_xref(name:"IAVB", value:"2018-B-0136-S");

  script_name(english:"Citrix NetScaler Gateway Cross-Site Scripting Vulnerability (CTX232199)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler device is affected by a cross-site
scripting vulnerability. An attacker could leverage this vulnerability
to execute malicious client-side code within the security context of
the web server. Please refer to advisory CTX239002 for more
information.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX239002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix NetScaler Gateway version 10.5 build 69.003 / 11.1
build 59.004 / 12.0 build 58.7 / 12.1 build 49.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_access_gateway_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}
include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

if (app_info['enhanced'])
  audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.display_version);

var constraints = [
  {'min_version': '10.5', 'fixed_version': '10.5.69.3', 'fixed_display': '10.5-69.3'},
  {'min_version': '11.1', 'fixed_version': '11.1.59.4', 'fixed_display': '11.1-59.4'},
  {'min_version': '12.0', 'fixed_version': '12.0.58.7', 'fixed_display': '12.0-58.7'},
  {'min_version': '12.1', 'fixed_version': '12.1.49.1', 'fixed_display': '12.1-49.1'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_NOTE,
  flags: {'xss':TRUE}
);
