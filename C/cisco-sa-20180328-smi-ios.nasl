#TRUSTED 0b22f5e4f83b0c5b03e2e6c6c169ddab2e801a27adc6fe7d44cce0459534291023e61a0f9f98a4edee74b112531d361ea36084177b9d5b4b9512075f78a80a19c86702e6217fb14e6d72dfc461d0c057858d018f442bf7268d918b8248bc3a36813c9d3f6cda5da77a59824c2fff5d770a2bc970d72a1c259d31d008db65c0080efe64bf13949cf8ade464c9e7902efdf59de9b35df5fad844d5055568d7d22b0ac0aac59166d7d91333b2ef3d295a81820176f78fb81042d2026254d19cffa35ea219084558ee963b12b51ea9da006678416d2a7c6e02d79209768739faa6545ff1abc54492e9b8415a02f13c27d2f1e969ff9a7f5dd4dd082cc4a4e0dbb005e32769670e8a92292ad4853942963125850536c5ce48f91854438124ac37160924460fd58898c3082d2b4074b35ca818b4f3af315fba7ffeb06c7f35271274fdfd37c220a180f0c2924d0e898a1fc2ba69ccee88e6d01722277f9f7de27a7a35aa87aed8bc0cf230c4c82490c9f22b23f9152dcbce3eec84cee4672c6ca648e0c1d32b6f0b3144dda2f2f9c5b584d6a33c4ff3deb61dc568241142ca47f6a1aad39991bd676fbc51bf88fb6e6c7a93fcc5900e2f6b92fd14295c4bf8eca3bfffd5623816051223a545fa8f802b1a9bc43cb33b260b73391f0b1b6981263fc1ed8952f50db61834ba97ca945e2b8f476fe0955ef85c6614cd97290514939aef11
#TRUST-RSA-SHA256 61b3861e97390e4028ba4403554e46923aa93bf5af418c2341e02d7da4c742905cf44902623852e1c52ba77dd1fccb40bdfc5d51140937aad4427901b4ba0785ebe52b1bc975c7143ba709e405752bb305bcadfa6810779e961273fd8035e0a5512eb7fd15dc55eec57e43ca05419b28b6c72082011772d5948ede388c1a9e0ccf1e1dbe197cefdd2a69a6865e5928ee6f99493e89e97ce28dc76cef07185916c6c59aebd78a8008398142b1aa0517270d47b4b355132b2a4a4bf2825b8221616c0b2746d02ffc4eeb5798934eaa25c92e06d495cf8a14d5bb19bafdc90fc37dfa52e6479a33cb436d8e09ea4203ff199a1467f75ecf728ddc4e971dcde4d650c67c0890a64239f3c28c47cd8d34841f0178d95b7f4c19f18bee397e142ae5a531e12ac95e0c55a5574a45f37ca483833917c03f7fc54998d13a655ec7a6e874d0e6f933d923e19d176288fa8f5a13effbcf24e164e5a8433bf8fcb8fcc8d392041e5e12fbc3d7fb5f9ba5fbd6917e84c28d46800f06c2f081afd979c38a53d9c6c6eff0f98f41a31ed9ecc99f93ca8687ac596e6d9c9d4590191407cced0d0fc4a7ff7a92c641cb172e3592c5fa7c158e26004ffcf2ac9d04e19d402b3d8c96c04fc47684e3216e240ff9d3ca7e9ca2da82890c92f481b70e84e4bd9e7217d9d980c29e5993689c0d4677d048cfe1b04852465af5472174684a1c9c33914708
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131322);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0156");
  script_bugtraq_id(103569);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd40673");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-smi");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS Software Smart Install DoS (cisco-sa-20180328-smi)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the Smart
Install feature due to improper validation of packet data. An unauthenticated, remote attacker can exploit this by
sending a crafted packet to an affected device on TCP port 4786 in order to cause the device to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c08d6c6a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd40673");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd40673.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0156");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '12.2(55)SE',
  '12.2(55)SE3',
  '12.2(55)SE2',
  '12.2(58)SE',
  '12.2(55)SE1',
  '12.2(58)SE1',
  '12.2(55)SE4',
  '12.2(58)SE2',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '12.2(55)SE7',
  '12.2(55)SE8',
  '12.2(55)SE9',
  '12.2(55)SE10',
  '12.2(55)SE11',
  '12.2(55)SE12',
  '12.2(55)EX',
  '12.2(55)EX1',
  '12.2(55)EX2',
  '12.2(55)EX3',
  '12.2(55)EY',
  '12.2(55)EZ',
  '15.0(1)EY',
  '15.0(1)EY2',
  '15.0(1)SE',
  '15.0(2)SE',
  '15.0(1)SE1',
  '15.0(1)SE2',
  '15.0(1)SE3',
  '15.0(2)SE1',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.0(2a)SE9',
  '15.0(2)SE10',
  '15.0(2)SE11',
  '15.0(2)SE10a',
  '15.1(2)SG',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.1(2)SG8',
  '15.0(2)EX',
  '15.0(2)EX1',
  '15.0(2)EX2',
  '15.0(2)EX3',
  '15.0(2)EX4',
  '15.0(2)EX5',
  '15.0(2)EX6',
  '15.0(2)EX7',
  '15.0(2)EX8',
  '15.0(2a)EX5',
  '15.0(2)EX10',
  '15.0(2)EX11',
  '15.0(2)EX13',
  '15.0(2)EX12',
  '15.2(1)E',
  '15.2(2)E',
  '15.2(1)E1',
  '15.2(3)E',
  '15.2(1)E2',
  '15.2(1)E3',
  '15.2(2)E1',
  '15.2(2b)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(2)E2',
  '15.2(2a)E1',
  '15.2(2)E3',
  '15.2(2a)E2',
  '15.2(3)E2',
  '15.2(3a)E',
  '15.2(3)E3',
  '15.2(3m)E2',
  '15.2(4)E1',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(4)E2',
  '15.2(4m)E1',
  '15.2(3)E4',
  '15.2(5)E',
  '15.2(3m)E7',
  '15.2(4)E3',
  '15.2(2)E6',
  '15.2(5a)E',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(4m)E3',
  '15.2(3m)E8',
  '15.2(2)E5a',
  '15.2(5c)E',
  '15.2(3)E5',
  '15.2(2)E5b',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(5a)E1',
  '15.2(4)E4',
  '15.2(2)E7',
  '15.2(5)E2',
  '15.2(4p)E1',
  '15.2(6)E',
  '15.2(5)E2b',
  '15.2(4)E5',
  '15.2(5)E2c',
  '15.2(4m)E2',
  '15.2(4o)E3',
  '15.2(4q)E1',
  '15.2(6)E0a',
  '15.2(2)E7b',
  '15.2(4)E5a',
  '15.2(6)E0c',
  '15.2(4s)E1',
  '15.2(4s)E2',
  '15.0(2)EZ',
  '15.2(1)EY',
  '15.0(2)EJ',
  '15.0(2)EJ1',
  '15.2(5)EX',
  '15.2(4)JAZ1',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.2(2)EA',
  '15.2(2)EA1',
  '15.2(2)EA2',
  '15.2(3)EA',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(2)EA3',
  '15.2(4)EA3',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EA2',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.2(4)EC1',
  '15.2(4)EC2'
);

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd40673',
  'cmds'     , make_list('show vstack config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
);
