#TRUSTED 77d91e0ffdf631c964d61bc00ed3d48fb480c0b5a8904ad10028d136c8bc8a84809baeb3e490c5662077e390981c3e720bf80ea03f1e26f0c6ff2ecd2fdc785f43a87bb009536a78b0d4583475b7f9f97b1082f7f13a064c05d6b8003d0fab75ebfb6f85a28c19e6f0b9331cfeec490117dd246bf02f0505082818e180e806cc8ef2131a314f629aa45ca311378986255376ecad6965560ff7504dd5089bf110c2538ba33880f75f65501c5758ff156763e722de324a801285690fc805396fa13b923f9570adb92ed77bbfbdd4f0168db4f9155a1c743d025fd0e342be056e0b57a91f09b1043a3291475cc8b33549d44184c6762dea499e459bb874ba25c165c81be73f97c9327c537acedcf5ecaa25a9a89d68b14cc53a40acbd7d287260161fc0a11997a8ea4e6fd45ceed1dc906db1f42a038d346503f23fdec6d2dab33c775a6f45c0fca1b1e200c163f616a867762aaf156e3d9db7b20898ea3fc46daabc97eeacfce89e7725c4aabadd11afa357c76b7d0737780c0151b94e867e6eeef73373b0ba2ed9c7fea558dd7024538ba5a41da4be736dbd5443bcdff8ff62bcc00e9d441c2ee846841a503a932dd61a43741007fdc7c1c99ed25548394471c9526e83094b49aab3ce97ad3cced99d400663d5e17b4d09a9ed6b3a4de335caebe3aa04f9a70f02e3b2d0024629c4a13fd5e78f8858a50b8c4e84d5ccf152554c
#TRUST-RSA-SHA256 4719ba222617298eb51983322d0ccf7e5dd71eb1db72e4cca6e036a45a6ef6e8d3f2b1c4ee4b07ba41bb2629600934388858c93a7f7f21aae8a2f270e63aaf5e5b85df4a272ddb630ca0a10494fd61af86ccfb491302936493ea9af802504b2c7b400f694f755f1ff666e384ecaa5cd7f904ab1a014ea668cbd9bf360a4e775b2c175bbaee2ca8a76bea7aac29557e024f50ad92ee327ebbdfc6fdd6b84f5d88cb27e0e3ff636f476f12c7e74c96adf0be53f2d4d929e314147a15c815f2a9bd01fc11ced728322e947494510c000f71a966cfa5b412261d3afd24d9834dbe754161140b255fb1e025251b232fdebaae485e2f00c07d3c36d49c8e8b0bf4d9bf0e2863c7e06d3cd5508f72f2fedb0faad75b74d3846f6b2582c4ba67a3002caa292cfec19ff246edc42c6f44d310bd23a63ad80c5cd78c36018a0d427ad4b79df03d37e31b1927efb6938b32f9af7092e2365e3d8df6430666b6eabaccf4ed476a91771c6425d71095c041d0f4452cd71ab51737485cb2e56fd22fc1bce7054f013996276c0e10f87c1a74399376c89b78fd85c7d22806b1a092ce56047fd1ff3063aef646a0f16548178f4be09a416ae31ef35712e1ba1ae1002285cc407582d134a44d95dc32aa21bc9b6feb07826b723ad5911e351f73096b7e3bee2c615eb1fc542d2e91a118e61da15452f0dae01788e5db38d936eeb1448cc786935736
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152121);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3457");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt69369");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt74037");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-cmdinj-pqZvmXCr");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco ASA Software Command Injection (cisco-sa-fxos-cmdinj-pqZvmXCr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-fxos-cmdinj-pqZvmXCr)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance is affected by a vulnerability in the CLI
that allows an authenticated, local attacker to inject arbitrary commands that are executed with root privileges. The
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}
include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');
if (product_info.model !~ "(10|21)[0-9][0-9]")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '9.8',  'fix_ver': '9.8.4.29' },
  { 'min_ver' : '9.9',  'fix_ver': '9.9.2.80' },
  { 'min_ver' : '9.10',  'fix_ver': '9.10.1.40' },
  { 'min_ver' : '9.12',  'fix_ver': '9.12.4.3' },
  { 'min_ver' : '9.13',  'fix_ver': '9.13.1.13' }
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
