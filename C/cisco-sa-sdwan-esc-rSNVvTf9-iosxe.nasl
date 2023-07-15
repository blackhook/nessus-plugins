#TRUSTED 3badd0d9d666e844b6f6b4a0ea6ad91d57286054d5869152cec80c0cc5f725d5b6dc970660ecf258a1fef72ac7c068735d570e4122f3918bdb004cd910ed8ecda2743f17e8d512a192b0ddecd0754f87b46806c27cce7628536397682dbb402178a3cfe826a4a4a964431a50d6cf11a5c5ca796144c152c594ca0b0fe849044ec1105d232e64a27b3a7bc3c9995a8ee716953de1c1c92d278a24a765fa888f8ddb81c7c6d43cd5bb21f15892c13b36a4e0efb3aea55cd6d3ad708faeaf00ccf421879f3cd2fec25add29d624c54b525ea9bcb98702dd3ddd1f388b0646ffaa7ecd4ba8df5164f31e893dac55fade10ce3f12fe3ff57c32ce1fbbb6a121d7e6d8b8fb5df64af9f6e7e0871b8504f1de03b30eb3c4ce64abb610eaf5c0c78dabb256c060247f243848436858c8edcf5086f013a55ef72be1b7d5f3680ccd25fad1c749fad730928180e20c801c4692fd1f6abb5c20b1ae339ef158a7fc93e2d4ff5e767292f8e7e580e338a143cbb83c0554b25b63698e8c2b0b242927d86693389b7ffdcc2e47349e26ca14dc4fb035f692877e5dfc65d0a1137088220e4982cefa15abba08b09e3c77e3b4a91027ea24cd0e0552fd557d8ac4ce1da794e114c5cc22956c45a1ddffa92dd658c33e05c6ec0491167ca69add274c37f1f91b1e198600b028e1687bb60e6f4f4deb4f69ad89763b6749680b46b2fea296945288a9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151467);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/09");

  script_cve_id("CVE-2021-1371");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv43400");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-esc-rSNVvTf9");

  script_name(english:"Cisco IOS XE Software SD WAN Console Privilege Escalation (cisco-sa-sdwan-esc-rSNVvTf9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the role-based access control of Cisco IOS XE SD-WAN Software could allow an authenticated, local
attacker with read-only privileges to obtain administrative privileges by using the console port when the device is in
the default SD-WAN configuration. This vulnerability occurs because the default configuration is applied for console
authentication and authorization. An attacker could exploit this vulnerability by connecting to the console port and
authenticating as a read-only user. A successful exploit could allow a user with read-only permissions to access
administrative privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-esc-rSNVvTf9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ed89e18");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv43400");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv43400");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.1s',
  '16.12.1t',
  '16.12.2',
  '16.12.2a',
  '16.12.2r',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.2a',
  '17.3.1',
  '17.3.1a'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvv43400',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
