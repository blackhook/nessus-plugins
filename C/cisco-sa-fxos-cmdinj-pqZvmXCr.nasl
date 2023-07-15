#TRUSTED abb2cb6e67a2c9690d71b610d05a0ca73290c12f26d3a42adf4969c8d06d36d69e479a0385e46e358a9de388fcd6ff4297a68b9b16911e29a489b0e4dcd0c0174030fb2bb8896faed93905f76fa7a5e188671f522f05e1309944719887992d64ec18fee2cd413a781d646f3554348188c0fc931c8199e92a988c952cc74314a32a2628a7cfe9507679404f1b5dbdf0daf7db67c0b7379599988b6f42ae9ff18d15f3ec79f002eec7d8c08b0e9c62e0ed2580a6cde3ce9ee0c7bd69e4f5a8642ca4b4aad5ee7b61aad31170809379083f342e97935ebcb1d61bb8f240db49d580263848de0d94717e88b54779eb7c2e7836a7ca82cbc20a2d8acbb5a22c649abc7b810eb015190690cf1f3de5e0061c8d171056f9a7fc0a701ba4132e76bade4d35f0c46669f17f7a425604acb6a19f7217bd896d076971329570c6e4a71e6fc735fec58d150c8fc893f288cbc55214cd96cb54366e25a777b5ffb3287eb890b2c21f33d83d07de1029aaff2b9c6d63f09a89b544656ab04e176e2da4c33bbd2244c87242652618f22fb6bb112f68052405ee9ba4a0bd6fb9178339e268f088c4164146b63a12c495e70ebccb1a05ea850971150b1d031012a9aaa4ea6416a92a59ee5dae8f629b56fb85edff827856bde1cd9dbb67702f6110135e8ec34bed9f9173f84075f85198622be5468bc282aa754e78e43ada29f364475a6188b79024
#TRUST-RSA-SHA256 6d9817b7310e7310008d432ffac8e2e13a26f9eac7e8c9caf9ff9ca6971d4ff95d00e8e161257faf0b8975631b563181424e49b9b534b1aac104f1d952a0d1a39c7f7c84d1a46a86754e953d0e5063045081038eef5bb18253d0f328475bae6b198bbe391740ce41d7fc0057839386889914cc37f253be828ba3ff5dc7ab24c4016adb436612923ed11efe85540adbc4373e40740680bd2aed2f7045aab78e8ad66faf316486aab9e3257d3e8c67f68eba4361ceb96a53b4c74558852f8f0775e0cf45cb7b7e0adc044af8ec3970a84dc901c92bffb9db4a232411e252319229ec62263c75b53e041bcd045295d03d637376d3cfa8a30ccaae81a9b69a09464e7fd565f6b24b8dbda4830c1338fdb43d053bef4aca50f8667c52b43f20e6be77d7f128843a179f5371a409d839c83c77143a240bdf119e885992c9fca5d23131b123bbd020b34f5e880d18b8549e00ab666b8f9443fd33db26815edc193bae2995cc2510ba01877d655877de9e0848e0369cd89f5b2e0520104998d7ef79fe2ad101a859a19135ded51a42f42149e836a70c2250aefb0999dbc057d5d59ab2967e9271a636232b9afeda1058fe798f2aeb11771263245205d1da7e0385dab6977551508ac6394fa45d00e55bcb80ef2964f2e60e58d6071c1a6f6ebd44b6086c448f99f000e2cf20accc8a3d8bb13d2da8f8f3e718c1b2197c1f719da02bacb1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152122);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3457");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt69369");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt74037");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-cmdinj-pqZvmXCr");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco FTD Software Command Injection (cisco-sa-fxos-cmdinj-pqZvmXCr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-fxos-cmdinj-pqZvmXCr)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense is affected by a vulnerability in the CLI that
allows an authenticated, local attacker to inject arbitrary commands that are executed with root privileges. The
vulnerability is due to insufficient input validation of commands supplied by the user. An attacker could exploit this
vulnerability by authenticating to a device and submitting crafted input to the affected command. A successful exploit
could allow the attacker to execute commands on the underlying operating system with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-cmdinj-pqZvmXCr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebab64e1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt69369");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt74037");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt69369, CSCvt74037");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var model = product_info.model;
if (empty_or_null(model))
  model = get_kb_item('installed_sw/Cisco Firepower Threat Defense/Lw$$/Chassis Model Number');

if (model !~ "(FPR|Firepower )" || model !~ "[^0-9](10|21)[0-9][0-9]")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0',  'fix_ver': '6.3.0.6' },
  { 'min_ver' : '6.4',  'fix_ver': '6.4.0.9' },
  { 'min_ver' : '6.5',  'fix_ver': '6.5.0.5' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt69369, CSCvt74037',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
