#TRUSTED 48794d48ec5aae797c99786a6482d415c50ed50f79dd312fc284e1644206a43b3a3044b69b12bbcb3ca34933d2dc31cec0c04fff0636ead7c09f8f6185aa3e8284ec8a76888202d129d4a1e6ef42da692324aca712a62492d7b5e7acea3524aa2a31d33c03f6fabd009d0c41977581d4b322aca48b78f678bf7e9eb615f211be2f8943dc9cde7422873c83321fc8977b1d97e5ed9db92672d2b9ec76b2d55b3e0774bd7cb18a5981889199720d58b50f832b8200c0be970959012ea4028c962884442e8d48ef4bd992b2f1e7fadf62f017240684543d5ac846f166bfa99dbc9608f931e3b4f0bd8540c7c3ac6c84a29adbc4b74bcc1f8c080043bf5ac92f5e64fce549a454c946c174a5fe7874dec411f807b487eb38e8c5366be3b26962fe82b1f87110d16629319d7be60e7fc1a118eb70eba1c4546c7dddd01612b52e5be8eda7d4ed3d467475c2d003246a6aa32006db3cdcb7cc6120027a7c0e5175f40236174d010a7612d6e0d264c36fc0d4ab4a672b7c497de08ee525d95865d6e32715f11f8e736da21b3121e9f0b8cbc9b40b3a31378bf72a7944416d63ec62329df03bbb3c51d80e45ea7dcf5250cfdcb7181ea77a2c7cb4aa8598b7e2052d1c020b84d072681b9f852e48a75775cd75f13a84f6751717545a4716bacbe04cfe77760f249548491f5321fcb6576bbeefca737aa9d247e13cb40b1792494426a103
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133726);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2019-1849");
  script_bugtraq_id(108342);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk35997");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-iosxr-evpn-dos");

  script_name(english:"Cisco IOS XR Software BGP MPLS-Based EVPN Denial of Service Vulnerability (cisco-sa-20190515-iosxr-evpn-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a vulnerability in the Border Gateway 
Protocol (BGP) Multiprotocol Label Switching (MPLS)-based Ethernet VPN (EVPN) implementation of Cisco IOS XR Software
could allow an unauthenticated, adjacent attacker to trigger a denial of service (DoS) condition on an affected device.
The vulnerability is due to a logic error that occurs when the affected software processes specific EVPN routing
information. An attacker could exploit this vulnerability by injecting malicious traffic patterns into the targeted
EVPN network. A successful exploit could result in a crash of the l2vpn_mgr process on Provider Edge (PE) device members
of the same EVPN instance (EVI). On each of the affected devices, a crash could lead to system instability and the
inability to process or forward traffic through the device, resulting in a DoS condition that would require manual 
intervention to restore normal operating conditions.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-iosxr-evpn-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79d65f6d");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk35997
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f37c1289");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk35997");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(754);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

var fix = NULL;
// set the fixed display for version 6.1.x and 6.2.x to 6.5.3 
// since we can't do this by using version_max and fixed_display as we do with vcf.inc
if (product_info['version'] =~ "^6\.[12]\.") 
  fix = '6.5.3';

vuln_ranges = [ 
  {'min_ver' : '6.1.0', 'fix_ver' : '6.3.0'},
  {'min_ver' : '6.3.0', 'fix_ver' : '6.3.3'},
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.2'},
  {'min_ver' : '6.5.0', 'fix_ver' : '6.5.2'},
  {'min_ver' : '6.6.0', 'fix_ver' : '6.6.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['BGP_MPLS-based_EVI'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk35997',
  'fix'      , fix
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
