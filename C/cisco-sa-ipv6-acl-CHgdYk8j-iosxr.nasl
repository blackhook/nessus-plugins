#TRUSTED 0c9760c818af55084c1f215b88281abf2d2fd842d703e2823bcfe32421d4d86e0cfe66d6413ebf1c27e139a6f5ec44a87b95062776c68a278040905000f4dd7f27d1d4767840bd91e786f0576869566eec977fabbb9134358fa84a564bfe0b96c5f805ddf175270cdc391e7030db37f0731fb21556fa87d32cf9b443d06aab16d8d97a8d496446a1fd639ac869a96c23a373167cd1911a7fe46d3c59bbbe02f6d91a2b027ed74d2a9bf8772c99620a965ba6d4e44aceafe861e9f714a527ece4d16b5e373862282c3ea378b27197074374fe768560d9e7e2bd1c2466b67714fb8c6208127bd9b3b8ad6d74952c1a8675c26c980674047135ea7d5aa9187c4811aa9ad6547d39ceee64e17d2342259d0e07322ff8c5a8b4a694a2adc02d031d34285985b09b48e962a794faf42e8267b43d9234e2dad0ca709c81261743730dfebc4083b084fe8407c7223ecb3e194b1eae4717780ce0ca7a42d4cd7c211ba60d26ce8ba54350df0664aa2f4dc3c3bd3bb5a51fbc50ea19cca3ff9ba57015f92fdc4ffd507d2996d0accfca128dd1ba1b85c77701efb30b70b8e9316f647aa2110041753231012f5c7a698e7eb41035e55f39b2b00bee757199655c62f2c0ac35b02c323f0f5343041a70abd3d170005bdd3ce7ed0d26cc6d7a5860c12ec723480f57a5c4730e0268010ab3f5061ac0ef3354fbdc2d269fee0eb5bf4abb0b8975
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146480);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2021-1389");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm55638");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ipv6-acl-CHgdYk8j");
  script_xref(name:"IAVA", value:"2021-A-0073");

  script_name(english:"Cisco IOS XR Software IPv6 Access Control List Bypass (cisco-sa-ipv6-acl-CHgdYk8j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the IPv6 traffic processing of Cisco IOS XR Software for certain Cisco devices could allow an
unauthenticated, remote attacker to bypass an IPv6 access control list (ACL) that is configured for an interface
of an affected device. The vulnerability is due to improper processing of IPv6 traffic that is sent through an affected
device. An attacker could exploit this vulnerability by sending crafted IPv6 packets that traverse the affected device.
A successful exploit could allow the attacker to access resources that would typically be protected by the interface ACL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-acl-CHgdYk8j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76e17295");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm55638");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm55638");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1389");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

display(tolower(product_info.model),'\n');

if (tolower(product_info.model) !~ "ncs\s?(540|560|55[0-9]{2})") 
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '6.6.3' },
  { 'min_ver' : '6.7.0', 'fix_ver' : '6.7.1' },
  { 'min_ver' : '7.1.0', 'fix_ver' : '7.1.1' },
  { 'min_ver' : '7.2.0', 'fix_ver' : '7.2.1' }
];

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "^\s*ipv6 access-list"};

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvm55638"
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
