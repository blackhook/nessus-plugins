#TRUSTED 23d1f902488d4b942b35eaca9b893b3e77acc46cd3c4780ec09f235b6afbbca911261449319e7163262ae3797e852f67fcf52a307ce9698adae9eae4fd4cfe825f9b2625b2d496ce295508100798d565918aa8c8c84a5ac644a4e13c07713d4cb5c77011608603af214061417ce52c94a626e79e0e8f84f3e298c502d30f41157ad22dee59da3a407668524b1ff94e94880816a2d4f518e8e8cb3e5809af301ef9e55bbb926b84156c4d916aa0540e6bf68136c359a4a583b4c7413c25054c6d9fd363cb77682e2ebf87f4f154ff15a2c58639f28ee89872ae1513f54ed80128f6520a0d2b46a08e2ce22f0dcdfedfee32984db890ed818f32d7638ef0a1f0eaf4e0488c9c757210fab762977afe329e11e23301d045a1a3f27f9cae31cdc863981b59d3ef0339522696c40150c9918fd3d3964463079fb9c020ad3563f7cc276ec1e120cd8278b22bcf5a95fba849b327facb42510c3d4eb62fb555bff5ed5fac69fce1d5312f6ea00a5cf2d83d67208ded6e4a21e9dce0289eef5696115a712a3b2c07fec01fdaa364ff9a6a855ae2ad0f65bbb86229ce2c9880f52cc3880ea1f999565b52628688905246909a7073ad951f9eb825e4aafea767d7215561341db46e48ba87db12226ba6a52f17b8e1beab0f3423dcca7d8efbf57ead66ec00144c64508036b983e58358e679a757d2a6bc5f8a9468450ca931d398f5d8c910
#TRUST-RSA-SHA256 64ea649c3a5d8301710985322a53f80cc5e2e7ae626df4255da7234708fcfb6d23db6d0d02dece5d6c373ded86555a2707a5816cf049d5b9d77c7408276aed28bd5becbb24250ea83941928b0375a58987452d448395cc7bf14bbcfa15474983c44baec28c40adae207c175aa255e6837007d6af9599ae567b0301656ee45aada7dfb0ae93dde0ae4df8266e90d9563c06e49257acd92c566907aab44be041747d35414c37f7e8c1fa34305760bab5339aa15932171db192181bd05ebda3a410f5e711b03cdb18ef79c9eb3b46212fc37dc667c9c6720cbe684894f4bee31eb49e5412297efd9959b3e2141ffe78118e72acaa2ae3be0abf12aa0caf9b00d152f44f623171b0aa1e1ec99c30981bae50b84aa3cf9154147d4fc2f7fcb2f6c85b6a3fd89eca677c193e4b4d32a576483c0ea54e9167a30c95bd627f9bc1cdb978678458b3e73546ee361eeacff2368d5cd53e9e4b2412e372b07504226917181377c3b27542fa55d1b30bd6e720d7e8fd50f06c08c79f554ab71b7c715dbf53fce19824427a7f3dbc110a6d589d46fdfd9c563339949916e3bf123982065f69b51361d15c03e0e425f5c4d0669b6612c3243aa79e36d312e87144d3af358f2fde98120f7654b7c2a9c6738c78abd3d1b27a17b5c06b0e9f1bd16d204589e07b5153bc1532806001e45ba4d63f6856e03d127a87be977c0286d043c5b05cd1089b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165678);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20919");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa96810");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-cip-dos-9rTbKLt9");

  script_name(english:"Cisco IOS Software Common Industrial Protocol Request DoS (cisco-sa-iosxe-cip-dos-9rTbKLt9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the processing of malformed Common Industrial Protocol (CIP) packets that are sent to Cisco IOS 
Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to 
unexpectedly reload, resulting in a denial of service (DoS) condition. This vulnerability is due to insufficient input 
validation during processing of CIP packets. An attacker could exploit this vulnerability by sending a malformed CIP 
packet to an affected device. A successful exploit could allow the attacker to cause the affected device to 
unexpectedly reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-cip-dos-9rTbKLt9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e302623");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa96810");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa96810");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(248);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var version_list=make_list(
  '15.1(3)SVS',
  '15.1(3)SVT1',
  '15.1(3)SVT3',
  '15.1(3)SVT4',
  '15.1(3)SVU1',
  '15.1(3)SVU2',
  '15.1(3)SVU10',
  '15.1(3)SVU11',
  '15.1(3)SVV1',
  '15.1(3)SVV2',
  '15.1(3)SVW',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(7)E0b',
  '15.2(7)E3a',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.2(234k)E'
);

var workarounds = make_list(CISCO_WORKAROUNDS['cip_enabled']);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa96810',
  'cmds'    , make_list('show cip status', 'show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
