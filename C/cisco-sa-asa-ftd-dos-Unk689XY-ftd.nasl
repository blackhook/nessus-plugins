#TRUSTED 9b97bbc90ef425af648ac369a921037ff7c077cb375653e38084185c5d766c203e252ff7c5c086c4614a93e10fd1423f05c9f5a3c2956f1a30ecda2cee5f017d401b6fbced78b3d1beac1616fbcc26f15bbb6b336004e38a8193560c64eb2141efa36cd73bb8807eb487c6d35bb33be3bddd9bbe7243baa1a8bdc8babf84241d6069fc116b95c3c2e8ffb8e3f14309d0b0b8d06d4294562003d4c4b53a7aa6000e53dbbf6310cf84e10a263c5ec41aef87f5bf0717b13975b5e99253651c0c40a3f4614238b76444b964a29d10eb4c1f5c042755804d4baccd4a374a5f50a4398b2b6fa333bae0fd60b1f2a59aadd8afd1f6a8c90b2f00808c0787545890bbee8be0d6f360c2f344048763a1048326f12f5a57bb451af90489ee20ec962d7b54218cf5aecb89db65698de47ccff3e58dfbbd7202f652992b283f89a526590e4d7e7b95b38da1a2cbc48927ec552dd269ba81d7d56c366cbbe26e98f6352e22fd87c03cab64cf46611e7ddcc044e92349c717002b6f760f61cc7ca5b3c841fce0ff16a1d20c9c1fb4d9b314a770880b4c835e3572bd04473e66771dd8aa883bd8b05c3a14f2f759cd531095779ac6caae61b0a8f66da9a1aa730e77ead93959977a07801f48e38935e3c3df3d37780c2fe2a2f97dd404ad6a3cfa4aebf8f3221d9a1ed8ac9101bd5c0d22372fa13fed42780b9f3ef1920c4609d2e9ecb6ce9a15
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155369);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-34792");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx79526");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-dos-Unk689XY");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense Software Resource Exhaustion DoS (cisco-sa-asa-ftd-dos-Unk689XY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service (DoS) vulnerability in
memory management due to improper resource management when connection rates are high. An unauthenticated, remote
attacker can exploit this, by opening a significant number of connections, in order to cause a denial of service (DoS)
condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-dos-Unk689XY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01162636");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx79526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx79526");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.6.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx79526',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
