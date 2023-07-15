#TRUSTED 97be187bbe386f189fddd00174611e044da4ab284eaa97bccd6713a102cf394cf92906fcafb1f3485c054f2b325950d01aa60e34a65cfb4f65722b443c06715cd464f08a2ad9d4fbf5a897da8818da9bb74b21bcecada5fef93c8c00d4d9153967f233c6d6ed90904b2ae6b71c163b19810aa881ad9a1b6976691198c9fd64d21e111ceb58de585067c3d325943f64943bef10ccc5c71aacc6896eb96a13fbea17a817df1aeecdf474b5c229c505716c3780fdb69f639a833058e30c4b6193bc5ee9d46dea404443f06913a33b3e5c4068ba3f523d3d2aca5d6aea42b22273eb43b0e41c24143e5971e3daccef19e3d5abea0f7bbadb5a51ba1578f79b95764dc9000c6b2951c7ca03e8dd635b9b0f53550b953c412b22865a74c65031c42847e1d2175b7aa7685a886965cd9f2aeb6211a7d7177734a3859231f6a0ee68a8f556789a88f75c39c87f053a320c0d8fe4ecc16e27cb58fdabb6cadc8519b0654b157d7b92546b40366a607df73476df78c4fd317c32bbee03041becd591772cac34aec7fe8a65ed8c5b79cda7e0db1a43d0e8aef0b0770794f291ee4539449813413683ffd762a326e40672d741572de578c3eaf07da24522a3fa4f91bcf26769d1740909abd919bbadcc4699343dbdf8e4ea9af53895bf0275d8ae63e85f4487a2e1fb5d10bea3262c74cfe6c5ba6d54d0dcd2af3aecd3774d1abd4e06b2b5ce
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133473);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2018-0485");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva23932");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi95007");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-sm1t3e3");
  script_xref(name:"IAVA", value:"2018-A-0312-S");

  script_name(english:"Cisco IOS XE Software SM-1T3/E3 Service Module DoS (cisco-sa-20180926-sm1t3e3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the SM-1T3/E3 firmware due to improper handling of user input. A remote, unauthenticated attacker can exploit this,
by first connecting to the SM-1T3/E3 module console and entering a string sequence, causing the device to reload and
resulting in a DoS condition.

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

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
  '3.9.1S',
  '3.9.2S',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.8S',
  '3.13.9S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.8.1',
  '16.8.1s'
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
