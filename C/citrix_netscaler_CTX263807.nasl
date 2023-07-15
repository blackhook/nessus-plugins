#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166623);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2019-0140");

  script_name(english:"Citrix ADC and Citrix Gateway Buffer Overflow (CTX263807)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 11.1.x prior to 11.1-64.11, 12.1.x prior to 12.1-56.22, 
13.0.x prior to 13.0-58.30. It may be, therefore, affected by a buffer overflow vulnerability in firmware for Intel(R) 
Ethernet 700 Series Controllers. This may allow an unauthenticated user to potentially enable an escalation of 
privilege via an adjacent access.

Please refer to advisory CTX263807 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX263807");
  script_set_attribute(attribute:"solution", value:
"Please refer to advisory CTX263807 for more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0140");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
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

var model = get_kb_item_or_exit('Host/NetScaler/Model');

# MPX                         SDX 
#13.0 build 58.30 and later / 13.0 build 58.30 and later
#12.1 build 56.22 and later / 12.1 build 57.18 and later
#11.1 build 64.11 and later / 11.1 build 65.10 and later
if (model =~ "MPX")
{
  var constraints = [
    {'min_version': '11.1', 'fixed_version': '11.1.64.11', 'fixed_display':'See vendor advisory'},
    {'min_version': '12.1', 'fixed_version': '12.1.56.22', 'fixed_display':'See vendor advisory'},
    {'min_version': '13.0', 'fixed_version': '13.0.58.30', 'fixed_display':'See vendor advisory'}
  ];
}
else if (model =~ "SDX")
{
  var constraints = [
    {'min_version': '11.1', 'fixed_version': '11.1.65.10', 'fixed_display':'See vendor advisory'},
    {'min_version': '12.1', 'fixed_version': '12.1.57.18', 'fixed_display':'See vendor advisory'},
    {'min_version': '13.0', 'fixed_version': '13.0.58.30', 'fixed_display':'See vendor advisory'}
  ];
}
else
  audit(AUDIT_DEVICE_NOT_VULN, model);

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
