#TRUSTED 73184e9fd4397e6a2147a22fa0a77715123cbe81b2a96b110c2b70e5e476a52e555d90762fffb9546ec605d699b9f4409bbb3c0c9d65fd8ffd958403a1252796f615af59925d3ad9e5f2d693717a9e996dddc18cca687f4ba4bd05ad45beead2b70fa2006e17b34e139c2f12150fa5d908679a17c2299a24d9bb69cb0f13842c1ee4a74a62c02c7585fce79cda912a8d662347ba3ebc427026b581ad4c823aa56e8075faa6d1440f59c615253ed94995e1c89bcbf62368d698bfbaa099cad6f7df7d9f1dbd11c12d170f7b1890a10b95f3b177c62d7af0eefe216d7ff376e80c84804f4d2254ad57c700bddd53f188db7251ffbb08a369dcdc6d8721975173cc457ae1b8b3a5ef3c03a44fd6bc21268ef2f551149312f7b8e9f1682248052d07b6e072330bd0e31aaf544ac37288bfcc5372c30177603dfe3ca0b1283578741c08605b0c018c45074506efe3ad2374569be95c9fe33b8bd9f4dadf82c51b9d1946a9aef7b2be46032346d3491067103e2b240f41084ca6a89861d858c601d2216dc487ceb21ad844b4ad6580e019a5846e318bd6f5b23b9732780745e1e1b0edda28b0384a76e75471616d44c947c6497cfc7fd6bd09effb50cc863efb6ad549a8ae36a67bd109f06106a46ddacea8efb3e1cc52f0499e0ec2a48bcaf86173809a8895453fd9dd195b0f2bf0c9149d3123282b4ae16eba3cddbc883f586d250c
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146481);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2021-1389");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv45698");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ipv6-acl-CHgdYk8j");
  script_xref(name:"IAVA", value:"2021-A-0073");

  script_name(english:"Cisco NX-OS Software IPv6 Access Control List Bypass (cisco-sa-ipv6-acl-CHgdYk8j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the IPv6 traffic processing of Cisco NX-OS Software for certain Cisco devices could allow an
unauthenticated, remote attacker to bypass an IPv6 access control list (ACL) that is configured for an interface of
an affected device. The vulnerability is due to improper processing of IPv6 traffic that is sent through an affected
device. An attacker could exploit this vulnerability by sending crafted IPv6 packets that traverse the affected device.
A successful exploit could allow the attacker to access resources that would typically be protected
by the interface ACL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-acl-CHgdYk8j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76e17295");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv45698");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv45698");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('nexus' >!< tolower(product_info.device) || product_info.model !~ '^(95[0-9]{2}|36[0-9]{2})')
  audit(AUDIT_HOST_NOT, 'an affected model');
    
if (product_info.model =~ '^95') {
  version_list=make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(5w)'
  );
}    
if (product_info.model =~ '^36') {
  version_list=make_list(
    '7.0(3)F3(1)',
    '7.0(3)F3(2)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(4)',
    '9.3(5)',
    '9.3(5w)'
  );
}

reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv45698',
  'severity' , SECURITY_WARNING,
  'cmds'     , make_list('show ipv6 access-lists'),
  'fix'      , 'See advisory'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_ipv6_access-lists'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
