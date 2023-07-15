##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163514);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-27509");
  script_xref(name:"IAVA", value:"2022-A-0297-S");

  script_name(english:"Citrix ADC and Citrix Gateway 12.1.x < 12.1-65.15 / 13.0.x < 13.0-86.17 / 13.1.x < 13.1-24.38 Unauthenticated Redirection (CTX457836)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by a unauthenticated redirection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 12.1.x prior to 12.1-65.15, 13.0.x prior to 13.0-86.17 or
13.1.x prior to 13.1-24.38. It may be, therefore, affected by a vulnerability that allows an attacker to redirect the
user to a malicious website upon clicking an attacker-crafted link.

Please refer to advisory CTX457836 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX457836");
  script_set_attribute(attribute:"solution", value:
"For versions 12.1.x, 13.0.x and 13.1.x, upgrade to 12.1-65.15, 13.0-86.17 and 13.1-24.38, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_netscaler.inc');

# Not checking config for VPN (Gateway) or AAA virtual server
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '12.1', 'fixed_version': '12.1.65.15', 'fixed_display':'12.1-65.15'},
  {'min_version': '13.0', 'fixed_version': '13.0.86.17', 'fixed_display':'13.0-86.17'},
  {'min_version': '13.1', 'fixed_version': '13.1.24.38', 'fixed_display':'13.1-24.38'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
