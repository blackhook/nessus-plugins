##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161773);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_cve_id("CVE-2022-27508");
  script_xref(name:"IAVA", value:"2022-A-0223");

  script_name(english:"Citrix ADC and Citrix Gateway 12.1-64.16 DoS (CTX457048)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is may be affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 12.1-64.16. It may, therefore, be affected by a denial of
service (DoS) vulnerability. If the device is configured as a VPN (Gateway) or AAA virtual server, an unauthenticated
remote attacker can cause uncontrolled resource consumption on the device.

Please refer to advisory CTX457048 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX457048");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 12.1-64.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_netscaler.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'equal': '12.1.64.16', 'fixed_display':'12.1-64.17'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
