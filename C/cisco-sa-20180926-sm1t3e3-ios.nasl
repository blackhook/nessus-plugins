#TRUSTED 47ced0bc37443eb735d9946367061357520e2d349b892f3859ab7421f20bb888984288d2d96022a3ea1e52f13f50697e59b19191e358482ef9875721e854abaca4a66755e5e49e02a10dafcc945ce432d45ee60d31039c4d5ce51acbff9e8663bc0b557088b7aab82f19857eb9d7411c25842488d694152fadae6f0cc6fe21098c05ce286a08a6483f33d87303654fcfe18084c4d877a5ef3a9679ea51e4ca488d8026e3c034d7eba1a08e8003c576ed3082c245687a6b3632ad1081fbba809f66e9d4a70fe12e6c4f3a702bd7fef428cfde697c4d7fa081d357419f796558ae4090f3593c91591fc6f5e4eb4e864a45b04fc95c65a0ede4f0c83991f337ff3274693685eed20bc42b4d84f9c22db4f3b8b837a44a4797a68bca882336ce558fae68898abdc9ccf31607f71841c85750902cd89de92ab83778b5f37f3918e57b8152e7dc2107d8240eb0d72166f6fc2f4c536ec49745d4d337d576447131416e4f2a2172f2c69478fe4b969358fd5081825c1e51402f5885eb231ced93e8673be10954e3829a7bdc04e0dfe2fbf3175e2c5ead08b532f8434e7b7efb36a2d0f3f5e8e111403039869d55b961ce8b8bb76d434d7dab4429e6ee0851a90e78d11b8e5749205407dd37db47cd6c7ff087e4397379ae1399c7eebb01961ecb8a53f67dc35ebe12946a139c93d3dd6d001588ed1468a0261fe420f4afa803e0eb8196
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133472);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2018-0485");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva23932");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi95007");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-sm1t3e3");
  script_xref(name:"IAVA", value:"2018-A-0312-S");

  script_name(english:"Cisco IOS SM-1T3/E3 Service Module DoS (cisco-sa-20180926-sm1t3e3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the
SM-1T3/E3 firmware due to improper handling of user input. A remote, unauthenticated attacker can exploit this, by first
connecting to the SM-1T3/E3 module console and entering a string sequence, causing the device to reload and resulting in
a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-sm1t3e3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e768df6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva23932");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi95007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva23932 and CSCvi95007 or apply the workaround
mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

model = toupper(product_info['model']);

if ('ISR4451-X' >!< model && 'G2' >!< model)
  audit(AUDIT_HOST_NOT, 'a vulnerable model');

if ('ISR4451-X' >< model)
{
  workaround_params = {'ISR4451-X' : 1};
  cmd = 'show diag all eeprom';
}
else
{
  workaround_params = {'G2' : 1};
  cmd = 'show version';
}

version_list = make_list(
  '15.3(1)T',
  '15.3(2)T',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.3(1)T3',
  '15.3(1)T4',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.3(2)T3',
  '15.3(2)T4',
  '15.2(4)M',
  '15.2(4)M1',
  '15.2(4)M2',
  '15.2(4)M4',
  '15.2(4)M3',
  '15.2(4)M5',
  '15.2(4)M8',
  '15.2(4)M10',
  '15.2(4)M7',
  '15.2(4)M6',
  '15.2(4)M9',
  '15.2(4)M6b',
  '15.2(4)M6a',
  '15.2(4)M11',
  '15.2(4)GC',
  '15.2(4)GC2',
  '15.2(4)GC3',
  '15.4(1)T',
  '15.4(2)T',
  '15.4(1)T2',
  '15.4(1)T1',
  '15.4(1)T3',
  '15.4(2)T1',
  '15.4(2)T3',
  '15.4(2)T2',
  '15.4(1)T4',
  '15.4(2)T4',
  '15.3(3)M',
  '15.3(3)M1',
  '15.3(3)M2',
  '15.3(3)M3',
  '15.3(3)M5',
  '15.3(3)M4',
  '15.3(3)M6',
  '15.3(3)M7',
  '15.3(3)M8',
  '15.3(3)M9',
  '15.3(3)M10',
  '15.3(3)M8a',
  '15.4(3)M',
  '15.4(3)M1',
  '15.4(3)M2',
  '15.4(3)M3',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(3)M6',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M8',
  '15.4(3)M9',
  '15.3(3)XB12',
  '15.5(1)T',
  '15.5(1)T1',
  '15.5(2)T',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.5(2)T4',
  '15.5(1)T4',
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(1)T3',
  '15.5(2)XB',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.3(3)JI',
  '15.3(3)JPI'
);

workarounds = make_list(CISCO_WORKAROUNDS['sm1t3e3']);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva23932, CSCvi95007',
  'cmds'     , make_list(cmd)
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
