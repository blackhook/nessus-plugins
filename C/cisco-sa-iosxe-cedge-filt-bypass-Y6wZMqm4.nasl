#TRUSTED 1f9407b85f1591aef6b413cad19fcc6730a37b519b46957831aa1c93d4ec41c4a6be0d53921d82fc21dec7c48a00f2b38870d6f7a55777b1713ca095888af23faed6e6e4ba1594bd8184dab90b792058f2d35a135f685c5d202abcf0fe80f1feefc024214c2bc4479526786350095d9914cc2147ecab7b7aa19ffdc2b49f7bda33a8c5480e9e7f10fd049b0381675f3d6afa8ff3d5af4610a645beb49b8a34fe73d339d4b547fb3f4d6d3395d8724b1e17ce40b0db3f8d140a7ff0ab3a3209c3432a6a64ff48912d8180f7fe395939de52dca8663bdaba832ac5c28f87a9394eb59d228231ce56a7b8ed7a0ad90b07752de2e7fcdf05fbc3a115286aa269b0ce6bbc8199ed796c2c778dbb9845ced88457b204671800eefa8780892909233327c4c5600f8f20d20341090f8000deca015bacc9839cf349196de69aa059caa3660e55a7949ab278d6eabc31167ebb75799ff0c120ba380194fe960880c4a29728f295b2cdc19458297752ac77c9c212cb35f98cd4ed2be8cc7715a4856a91427f08c7dfecf3ec7665eafab69738e2999c257042c6edd076543a94f6b47ad4566de5428c854eecbaf119571a5c302c63c4ca01116186046e16095fde6362c45c3c40f77adba74971711e3a6ee70e976fcfce0efed530b3e17dec4de6f278004517cb29de09ef93a4d06fbc7e3b4f3765a87eaf341a597e30a079f953cbf4704c1a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143154);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/23");

  script_cve_id("CVE-2020-3444");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw12895");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cedge-filt-bypass-Y6wZMqm4");
  script_xref(name:"IAVA", value:"2020-A-0540");

  script_name(english:"Cisco IOS XE Software Packet Filtering Bypass (cisco-sa-cedge-filt-bypass-Y6wZMqm4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a packet filtering bypass vulnerability.
The vulnerability is due to improper traffic filtering conditions on an affected device. An unauthenticated, remote
attacker could exploit this vulnerability by crafting a malicious TCP packet with specific characteristics and sending
it to a targeted device. A successful exploit could allow the attacker to bypass the L3 and L4 traffic filters and
inject an arbitrary packet into the network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cedge-filt-bypass-Y6wZMqm4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bafac99");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw12895");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw12895");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

if(report_paranoia < 2)  audit(AUDIT_PARANOID);

get_kb_item_or_exit('Host/Cisco/SDWAN');
var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# this vulnerability affected Cisco IOS XE Software releases 17.2.1 and later
var vuln_ranges = [
                    {'min_ver' : '17.2.1',  'fix_ver' : '17.3.4'},
                    {'min_ver' : '17.4.1',  'fix_ver' : '17.4.2'}
                  ];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['controller_mode_iosxe'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw12895',
  'fix'      , 'See vendor advisory',
  'cmds'     , make_list("show version")
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
