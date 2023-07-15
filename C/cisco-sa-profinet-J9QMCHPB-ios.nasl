#TRUSTED afeef9e24de8c687158106c8282b2a653c3e310b2e41d3a21c5ee25d6d032e91d2e028ff4040adeba2be5f5a8523f0c4b5c0decbc575373576b64d386843b0ae01493a4a74afdfb9b169018145dfc81854eec6df85a0b6d1a7595aa47448c7db17108b6d7439bd701b3c44b78b780e300a82adef496db7622f58804f2555ec20fb5446c8f3a1921f7a540470a85ee653186643c97908e86e1539df2d766c42591ef61c1640b35c49d6c0027d033f48eccd922f3db37929d8b2a8377aac871df933b301dae1f7b085774783e6056190b7fcc17e37b9b51b60d30dea33eb6a2fa44e4dec9ea3346564a362046cfeefb6cd91256780a296a6a9d5fa0611fdca0ad363d7f04b977ba8262fe1898e10054d817ac9a121d0527239628e95e00692a080c3c350e31f08844e946ce101b5afa127c47de20b9f08d3f0da7de093f254d81db541166664ecda3e13d960dd71571a4a1284dd263cb891ff58449e1335883dae4350187f07b996f03ec4a76a4a7899f94300436b4d62115a725412991c05de4d6b1b1fc008ebb1b3045bae84d8ec5c40effa7284349170623eb1e24c8db3485d7057b5964793e5bdc47b2bf3fccc15bafcf4e96b02c7e3eb2a0e94aa4da12c1b7dc2600f729abfa7ad3edee09ead74b7c9c6ecfc28040395c3d2589c9a8513031f605bdbea3e5b021510ebde035140bd22626759e8d644de360f3011e2a13991
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142473);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2020-3409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs48147");
  script_xref(name:"CISCO-SA", value:"cisco-sa-profinet-J9QMCHPB");

  script_name(english:"Cisco IOS Software PROFINET DoS (cisco-sa-profinet-J9QMCHPB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a denial of service vulnerability. An unauthenticated, 
adjacent attacker to cause an affected device to crash and reload, resulting in a denial of service (DoS) condition
on the device. Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-profinet-J9QMCHPB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cff4d72b");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr83393");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs48147");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr83393, CSCvs48147");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '12.2(52)SE',
  '12.2(52)SE1',
  '12.2(55)SE',
  '12.2(55)SE10',
  '12.2(55)SE11',
  '12.2(55)SE12',
  '12.2(55)SE13',
  '12.2(55)SE3',
  '12.2(55)SE4',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '12.2(55)SE7',
  '12.2(55)SE9',
  '12.2(58)SE',
  '12.2(58)SE1',
  '12.2(58)SE2',
  '12.2(60)EZ16',
  '15.0(1)EY',
  '15.0(1)EY2',
  '15.0(2)EX2',
  '15.0(2)EX8',
  '15.0(2)EY',
  '15.0(2)EY1',
  '15.0(2)EY2',
  '15.0(2)EY3',
  '15.0(2)SE',
  '15.0(2)SE1',
  '15.0(2)SE10',
  '15.0(2)SE10a',
  '15.0(2)SE11',
  '15.0(2)SE12',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.0(2)SG11a',
  '15.2(1)EY',
  '15.2(2)E',
  '15.2(2)E1',
  '15.2(2)E10',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(2)E5a',
  '15.2(2)E5b',
  '15.2(2)E6',
  '15.2(2)E7',
  '15.2(2)E7b',
  '15.2(2)E8',
  '15.2(2)E9',
  '15.2(2)EA',
  '15.2(2)EA2',
  '15.2(2)EA3',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.2(2b)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(3)E4',
  '15.2(3)E5',
  '15.2(3)EA',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(4)EA2',
  '15.2(4)EA3',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.2(4)EA7',
  '15.2(4)EA8',
  '15.2(4)EA9',
  '15.2(4)EC1',
  '15.2(4)EC2',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EA',
  '15.2(5a)E1',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2a',
  '15.2(6)E3',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7a)E0b',
  '15.3(3)JAA1'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "(^|\n)\s*profinet($|\r\n)"};

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr83393, CSCvs48147',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
