##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138212);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-18177",
    "CVE-2020-8187",
    "CVE-2020-8190",
    "CVE-2020-8191",
    "CVE-2020-8193",
    "CVE-2020-8194",
    "CVE-2020-8195",
    "CVE-2020-8196",
    "CVE-2020-8197",
    "CVE-2020-8198",
    "CVE-2020-8199"
  );
  script_xref(name:"IAVA", value:"2020-A-0286-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0057");

  script_name(english:"Citrix ADC and Citrix NetScaler Gateway Multiple Vulnerabilities (CTX276688)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix NetScaler Gateway device is version 10.5.x prior to 10.5.70.18, 11.1.x prior to 
11.1.64.14, 12.0.x prior to 12.0.63.21, 12.1.x prior to 12.1.57.18 or 13.0.x prior to 13.0.58.30. It is, therefore, 
affected by multiple vulnerabilities:

  - An authorization bypass vulnerability exists in Citrix ADC and NetScaler Gateway devices. An 
    unauthenticated remote attacker with access to the NSIP/management interface can exploit this to bypass 
    authorization. (CVE-2020-8193)

  - A code injection vulnerability exists in Citrix ADC and NetScaler Gateway devices. An unauthenticated 
    remote attacker with access to the NSIP/management interface can exploit this to create a malicious file
    which, if executed by a victim on the management network, could allow the attacker arbitrary code execution
    in the context of that user. (CVE-2020-8194)

  - A cross-site scripting vulnerability exists in Citrix ADC and NetScaler Gateway devices. An
    unauthenticated remote attacker can exploit this convincing a user to click a specially crafted URL, to 
    execute arbitrary script code in a user's browser session. (CVE-2020-8191, CVE-2020-8198)

In addition, Citrix ADC and Citrix NetScaler Gateway are also affected by several additional vulnerabilities including 
configuration-dependent privilege escalations, information disclosures, and a denial of service vulnerability. 

Please refer to advisory CTX276688 for more information.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX276688");
  script_set_attribute(attribute:"solution", value:
"For versions 10.5.x, 11.1.x, 12.0.x, 12.1.x and 13.0.x, upgrade to 10.5.70.18, 11.1.64.14, 12.0.63.21, 12.1.57.18 and 
13.0.58.30, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}
include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();

var constraints = [
  {'min_version': '10.5', 'fixed_version': '10.5.70.18', 'fixed_display': '10.5-70.18'},
  {'min_version': '11.1', 'fixed_version': '11.1.64.14', 'fixed_display': '11.1-64.14'},
  {'min_version': '12.0', 'fixed_version': '12.0.63.21', 'fixed_display': '12.0-63.21'},
  {'min_version': '12.1', 'fixed_version': '12.1.57.18', 'fixed_display': '12.1-57.18'},
  {'min_version': '13.0', 'fixed_version': '13.0.58.30', 'fixed_display': '13.0-58.30'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
