#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153223);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2021-21571",
    "CVE-2021-21572",
    "CVE-2021-21573",
    "CVE-2021-21574"
  );
  script_xref(name:"IAVA", value:"2021-A-0294");

  script_name(english:"Dell Client BIOS Multiple Vulnerabilities (DSA-2021-106)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Dell BIOS is affected by multiple vulnerabilities.

  - Dell UEFI BIOS https stack leveraged by the Dell BIOSConnect feature and Dell HTTPS Boot feature contains an 
    improper certificate validation vulnerability. A remote unauthenticated attacker may exploit this vulnerability 
    using a person-in-the-middle attack which may lead to a denial of service and payload tampering. (CVE-2021-21571)

  - Dell BIOSConnect feature contains a buffer overflow vulnerability. An authenticated malicious admin user with local
    access to the system may potentially exploit this vulnerability to run arbitrary code and bypass UEFI restrictions.
    (CVE-2021-21572, CVE-2021-21573, CVE-2021-21574)

Please see the included Dell Security Advisory for more information.");
  # https://www.dell.com/support/kbdoc/en-ie/000188682/dsa-2021-106-dell-client-platform-security-update-for-multiple-vulnerabilities-in-the-supportassist-biosconnect-feature-and-https-boot-feature
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02633955");
  script_set_attribute(attribute:"solution", value:
"Check vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21574");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(121, 122, 295, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_wmi.nbin");
  script_require_keys("BIOS/Version", "BIOS/Model", "BIOS/Vendor");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_name = 'Dell Inc.';
var app_info = vcf::dell_bios_win::get_app_info(app:app_name);
var model = app_info['model'];

# secure_boot must be disabled
if (app_info['secure_boot'] == 'enabled') audit(AUDIT_HOST_NOT, 'affected');

# vuln if either bios_connect or https_boot is enabled
if (app_info['bios_connect'] == 'Enabled' || app_info['https_boot'] == 'Enabled')
{
  var fix = '';
  # Check model
  if (model)
  {
    if (model == 'Alienware m15 R6') fix = '1.3.3';
    else if (model == 'ChengMing 3990') fix = '1.4.1';
    else if (model == 'ChengMing 3991') fix = '1.4.1';
    else if (model == 'Dell G15 5510') fix = '1.4.0';
    else if (model == 'Dell G15 5511') fix = '1.3.3';
    else if (model == 'Dell G3 3500') fix = '1.9.0';
    else if (model == 'Dell G5 5500') fix = '1.9.0';
    else if (model == 'Dell G7 7500') fix = '1.9.0';
    else if (model == 'Dell G7 7700') fix = '1.9.0';
    else if (model == 'Inspiron 14 5418') fix = '2.1.0';
    else if (model == 'Inspiron 15 5518') fix = '2.1.0';
    else if (model == 'Inspiron 15 7510') fix = '1.0.4';
    else if (model == 'Inspiron 3501') fix = '1.6.0';
    else if (model == 'Inspiron 3880') fix = '1.4.1';
    else if (model == 'Inspiron 3881') fix = '1.4.1';
    else if (model == 'Inspiron 3891') fix = '1.0.11';
    else if (model == 'Inspiron 5300') fix = '1.7.1';
    else if (model == 'Inspiron 5301') fix = '1.8.1';
    else if (model == 'Inspiron 5310') fix = '2.1.0';
    else if (model == 'Inspiron 5400 2n1') fix = '1.7.0';
    else if (model == 'Inspiron 5400 AIO') fix = '1.4.0';
    else if (model == 'Inspiron 5401') fix = '1.7.2';
    else if (model == 'Inspiron 5401 AIO') fix = '1.4.0';
    else if (model == 'Inspiron 5402') fix = '1.5.1';
    else if (model == 'Inspiron 5406 2n1') fix = '1.5.1';
    else if (model == 'Inspiron 5408') fix = '1.7.2';
    else if (model == 'Inspiron 5409') fix = '1.5.1';
    else if (model == 'Inspiron 5410 2-in-1') fix = '2.1.0';
    else if (model == 'Inspiron 5501') fix = '1.7.2';
    else if (model == 'Inspiron 5502') fix = '1.5.1';
    else if (model == 'Inspiron 5508') fix = '1.7.2';
    else if (model == 'Inspiron 5509') fix = '1.5.1';
    else if (model == 'Inspiron 7300') fix = '1.8.1';
    else if (model == 'Inspiron 7300 2n1') fix = '1.3.0';
    else if (model == 'Inspiron 7306 2n1') fix = '1.5.1';
    else if (model == 'Inspiron 7400') fix = '1.8.1';
    else if (model == 'Inspiron 7500') fix = '1.8.0';
    else if (model == 'Inspiron 7500 2n1 - Black') fix = '1.3.0';
    else if (model == 'Inspiron 7500 2n1 - Silver') fix = '1.3.0';
    else if (model == 'Inspiron 7501') fix = '1.8.0';
    else if (model == 'Inspiron 7506 2n1') fix = '1.5.1';
    else if (model == 'Inspiron 7610') fix = '1.0.4';
    else if (model == 'Inspiron 7700 AIO') fix = '1.4.0';
    else if (model == 'Inspiron 7706 2n1') fix = '1.5.1';
    else if (model == 'Latitude 3120') fix = '1.1.0';
    else if (model == 'Latitude 3320') fix = '1.4.0';
    else if (model == 'Latitude 3410') fix = '1.9.0';
    else if (model == 'Latitude 3420') fix = '1.8.0';
    else if (model == 'Latitude 3510') fix = '1.9.0';
    else if (model == 'Latitude 3520') fix = '1.8.0';
    else if (model == 'Latitude 5310') fix = '1.7.0';
    else if (model == 'Latitude 5310 2 in 1') fix = '1.7.0';
    else if (model == 'Latitude 5320') fix = '1.7.1';
    else if (model == 'Latitude 5320 2-in-1') fix = '1.7.1';
    else if (model == 'Latitude 5410') fix = '1.6.0';
    else if (model == 'Latitude 5411') fix = '1.6.0';
    else if (model == 'Latitude 5420') fix = '1.8.0';
    else if (model == 'Latitude 5510') fix = '1.6.0';
    else if (model == 'Latitude 5511') fix = '1.6.0';
    else if (model == 'Latitude 5520') fix = '1.7.1';
    else if (model == 'Latitude 5521') fix = '1.3.0';
    else if (model == 'Latitude 7210 2-in-1') fix = '1.7.0';
    else if (model == 'Latitude 7310') fix = '1.7.0';
    else if (model == 'Latitude 7320') fix = '1.7.1';
    else if (model == 'Latitude 7320 Detachable') fix = '1.4.0';
    else if (model == 'Latitude 7410') fix = '1.7.0';
    else if (model == 'Latitude 7420') fix = '1.7.1';
    else if (model == 'Latitude 7520') fix = '1.7.1';
    else if (model == 'Latitude 9410') fix = '1.7.0';
    else if (model == 'Latitude 9420') fix = '1.4.1';
    else if (model == 'Latitude 9510') fix = '1.6.0';
    else if (model == 'Latitude 9520') fix = '1.5.2';
    else if (model == 'Latitude 5421') fix = '1.3.0';
    else if (model == 'OptiPlex 3080') fix = '2.1.1';
    else if (model == 'OptiPlex 3090 UFF') fix = '1.2.0';
    else if (model == 'OptiPlex 3280 All-in-One') fix = '1.7.0';
    else if (model == 'OptiPlex 5080') fix = '1.4.0';
    else if (model == 'OptiPlex 5090 Tower') fix = '1.1.35';
    else if (model == 'OptiPlex 5490 AIO') fix = '1.3.0';
    else if (model == 'OptiPlex 7080') fix = '1.4.0';
    else if (model == 'OptiPlex 7090 Tower') fix = '1.1.35';
    else if (model == 'OptiPlex 7090 UFF') fix = '1.2.0';
    else if (model == 'OptiPlex 7480 All-in-One') fix = '1.7.0';
    else if (model == 'OptiPlex 7490 All-in-One') fix = '1.3.0';
    else if (model == 'OptiPlex 7780 All-in-One') fix = '1.7.0';
    else if (model == 'Precision 17 M5750') fix = '1.8.2';
    else if (model == 'Precision 3440') fix = '1.4.0';
    else if (model == 'Precision 3450') fix = '1.1.35';
    else if (model == 'Precision 3550') fix = '1.6.0';
    else if (model == 'Precision 3551') fix = '1.6.0';
    else if (model == 'Precision 3560') fix = '1.7.1';
    else if (model == 'Precision 3561') fix = '1.3.0';
    else if (model == 'Precision 3640') fix = '1.6.2';
    else if (model == 'Precision 3650 MT') fix = '1.2.0';
    else if (model == 'Precision 5550') fix = '1.8.1';
    else if (model == 'Precision 5560') fix = '1.3.2';
    else if (model == 'Precision 5760') fix = '1.1.3';
    else if (model == 'Precision 7550') fix = '1.8.0';
    else if (model == 'Precision 7560') fix = '1.1.2';
    else if (model == 'Precision 7750') fix = '1.8.0';
    else if (model == 'Precision 7760') fix = '1.1.2';
    else if (model == 'Vostro 14 5410') fix = '2.1.0';
    else if (model == 'Vostro 15 5510') fix = '2.1.0';
    else if (model == 'Vostro 15 7510') fix = '1.0.4';
    else if (model == 'Vostro 3400') fix = '1.6.0';
    else if (model == 'Vostro 3500') fix = '1.6.0';
    else if (model == 'Vostro 3501') fix = '1.6.0';
    else if (model == 'Vostro 3681') fix = '2.4.0';
    else if (model == 'Vostro 3690') fix = '1.0.11';
    else if (model == 'Vostro 3881') fix = '2.4.0';
    else if (model == 'Vostro 3888') fix = '2.4.0';
    else if (model == 'Vostro 3890') fix = '1.0.11';
    else if (model == 'Vostro 5300') fix = '1.7.1';
    else if (model == 'Vostro 5301') fix = '1.8.1';
    else if (model == 'Vostro 5310') fix = '2.1.0';
    else if (model == 'Vostro 5401') fix = '1.7.2';
    else if (model == 'Vostro 5402') fix = '1.5.1';
    else if (model == 'Vostro 5501') fix = '1.7.2';
    else if (model == 'Vostro 5502') fix = '1.5.1';
    else if (model == 'Vostro 5880') fix = '1.4.0';
    else if (model == 'Vostro 5890') fix = '1.0.11';
    else if (model == 'Vostro 7500') fix = '1.8.0';
    else if (model == 'XPS 13 9305') fix = '1.0.8';
    else if (model == 'XPS 13 2in1 9310') fix = '2.3.3';
    else if (model == 'XPS 13 9310') fix = '3.0.0';
    else if (model == 'XPS 15 9500') fix = '1.8.1';
    else if (model == 'XPS 15 9510') fix = '1.3.2';
    else if (model == 'XPS 17 9700') fix = '1.8.2';
    else if (model == 'XPS 17 9710') fix = '1.1.3';
    else
    {
    audit(AUDIT_HOST_NOT, 'an affected model');
    }
  }
  else
  {
    audit(AUDIT_HOST_NOT, 'an affected model');
  }
  var constraints = [{ 'fixed_version' : fix, 'fixed_display': fix + ' for ' + model }];
  vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
