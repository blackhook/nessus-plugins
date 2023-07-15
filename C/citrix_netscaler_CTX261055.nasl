#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149878);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2019-18225");

  script_name(english:"Citrix ADC Authentication Bypass (CTX261055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in Citrix Application Delivery Controller (ADC). An unauthenticated,
remote attacker can exploit this, via the web management interface, to bypass authentication and gain administritive
access to the appliance.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX261055");
  script_set_attribute(attribute:"solution", value:
"For versions 10.5.x, 11.1.x, 12.0.x, 12.1.x and 13.0.x, upgrade to 10.5.70.5, 11.1.62.8, 12.0.62.8, 12.1.54.13 and 
13.0.41.20, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
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
  {'min_version': '10.5', 'fixed_version': '10.5.70.8', 'fixed_display': '10.5-70.8'},
  {'min_version': '11.1', 'fixed_version': '11.1.63.9', 'fixed_display': '11.1-63.9'},
  {'min_version': '12.0', 'fixed_version': '12.0.62.10', 'fixed_display': '12.0-62.10'},
  {'min_version': '12.1', 'fixed_version': '12.1.54.16', 'fixed_display': '12.1-54.16'},
  {'min_version': '13.0', 'fixed_version': '13.0.41.28', 'fixed_display': '13.0-41.28'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);