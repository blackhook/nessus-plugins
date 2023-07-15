#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166617);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/28");

  script_cve_id("CVE-2021-22919", "CVE-2021-22927");

  script_name(english:"Citrix ADC and Citrix Gateway Multiple Vulnerabilities (CTX319135)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 11.1 before 11.1-65.22, 12.1 before 12.1-62.27 or 13.0 before 
13.0-82.45. It is therefore affected by multiple vulnerabilities: 

  - A vulnerability has been discovered in Citrix ADC (formerly known as NetScaler ADC) and Citrix Gateway (formerly 
    known as NetScaler Gateway). A session fixation vulnerability exists when a SAML service provider is configured 
    that could allow an attacker to hijack a session. (CVE-2021-22927)

  - A vulnerability has been discovered in Citrix ADC (formerly known as NetScaler ADC) and Citrix Gateway (formerly 
    known as NetScaler Gateway). These vulnerabilities, if exploited, could lead to the limited available disk space 
    on the appliances being fully consumed. (CVE-2021-22919)

Please refer to advisory CTX319135 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX319135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 11.1-65.22, 12.1-62.27, 13.0-82.45 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22927");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_netscaler.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '11.1', 'fixed_version': '11.1.65.22', 'fixed_display': '11.1-65.22'},
  {'min_version': '12.1', 'fixed_version': '12.1.62.27', 'fixed_display': '12.1-62.27'},
  {'min_version': '13.0', 'fixed_version': '13.0.82.45', 'fixed_display': '13.0-82.45'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);