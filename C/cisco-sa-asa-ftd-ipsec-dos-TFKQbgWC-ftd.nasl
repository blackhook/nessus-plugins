#TRUSTED 724ed068fc6b0cbdf60173d30d02c89bd32aaa335819165da3b6036a1421378db44a5960aa5c095ba024f4c7d46d3d48ac1216bfcc85da43b295387293ac8cb22bf5e1c666a3a915301d44d46ec6ede3aab6d21b3cddda0c6f6c9c817b2d15c7e3c425cb612fc17dfb9e3de04fbbccda30089eb3175443557097c421c5652cbe990a7a214cc91965a4118acf405704c10f3dafbaadced90388fb59eeab75cc9b8319e0e1b038bd38f5e0cf3e023bfa9dacbe52b02f1852debb6424880f2d041419c0fdb24505fa9d7746d65989eebc189acf573295c2471d0ad1cb283bf96ec15261f96234fd460bed5a6328855a3fdd696dded31cf6a17b584f6d661e19cd52f34c7e0b8a58a4ca85713ab904321c597c51538ef36cfbaf93efc86dc280e0be643110d172881c675fe3c67b380c84dfa44a0bf0efe8106c416a86eb96b986adbca6b9c3028152f40bf35d922c9b5af7b60445ecfae2aa00e3f832836c9e290cc8402121c5f22fb3bd2bcbd1ac01a5c0dda8452f75b1f8029dbb57d27a743a6ad3715b56f3ea722485063bc2eb5813cf1afd2e75b810ad6d46dbf73ce9af872d3a014983050e7a33141fa02e3f9dada88ff2fb347ff67474cccff6e2836967950a91c9bc0674a842e9eba88097c67d289b54cd44c4ac7ad971bba3d2046eb6cb64e72fb3e829196666d2e570d78003c66671a59b8925aa4f81dd844a723a13ad
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152025);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1422");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-ipsec-dos-TFKQbgWC");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy66711");
  script_xref(name:"IAVA", value:"2021-A-0337-S");

  script_name(english:"Cisco Firepower Threat Defense Software Release 7.0.0 IPsec DoS (cisco-sa-asa-ftd-ipsec-dos-TFKQbgWC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the software cryptography module of Cisco Adaptive Security Appliance (ASA) Software and Cisco
Firepower Threat Defense (FTD) Software could allow an authenticated, remote attacker or an unauthenticated attacker in
a man-in-the-middle position to cause an unexpected reload of the device that results in a denial of service (DoS)
condition. The vulnerability is due to a logic error in how the software cryptography module handles specific types of
decryption errors. An attacker could exploit this vulnerability by sending malicious packets over an established IPsec
connection. A successful exploit could cause the device to crash, forcing it to reload. Important: Successful
exploitation of this vulnerability would not cause a compromise of any encrypted data. Note: This vulnerability affects
only Cisco ASA Software Release 9.16.1 and Cisco FTD Software Release 7.0.0.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ipsec-dos-TFKQbgWC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b3df468");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy66711");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy66711.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1422");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
# Model ex: installed_sw/Cisco Firepower Threat Defense/L3Nsb3QgMQ$$/Model=Cisco Firepower 2110 Threat Defense (77)
# Model ex: installed_sw/Cisco Firepower Threat Defense/L3Nsb3QgMQ$$/Model=Cisco ASA5506-X Threat Defense (75)
if (
    product_info.model !~ "[^0-9]21[0-9][0-9]" &&
    'NGFW' >!< toupper(product_info.model) &&
    product_info.model !~ "ASA.*Threat Defense"
    )
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '7.0.0',  'fix_ver': '7.0.0.1' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy66711',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
