#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167253);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2022-32490");
  script_xref(name:"IAVA", value:"2022-A-0470");

  script_name(english:"Dell Client BIOS Improper Input Validation (DSA-2022-249)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, therefore, affected by an improper input
validation vulnerability. A local, authenticated attacker can exploit this vulnerability by using an SMI to execute
arbitrary code in the SMRAM.

Please see the included Dell Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000204685/dsa-2022-249-dell-security-update-for-dell-edge-gateway-and-embedded-box-bios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7018f4be");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:edge_gateway_3000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:edge_gateway_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:embedded_box_pc_3000");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_wmi.nbin");
  script_require_keys("BIOS/Model", "BIOS/Version", "BIOS/Vendor");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_name = 'Dell Inc.';
var app_info = vcf::dell_bios_win::get_app_info(app:app_name);
var model = app_info['model'];

var fix = '';
# Check model
if (model)
{
  if (model == 'Embedded Box PC 3000')
    fix = '1.15.0';
  else if (model == 'Edge Gateway 5000')
    fix = '1.19.0';
  else if (model =~ 'Edge Gateway 300[1-3]')
    fix = '1.9.0';
  else
  {
  audit(AUDIT_HOST_NOT, 'an affected model');
  }
}
else
{
  exit(0, 'The model of the device running the Dell BIOS could not be identified.');
}

var constraints = [{ 'fixed_version' : fix, 'fixed_display': fix + ' for ' + model }];
# Have a more useful audit message
app_info.app = 'Dell System BIOS for ' + model;

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
