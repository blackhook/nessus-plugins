#TRUSTED 0d16f7f8e77aac936905e9441608da85d4cbdc379a86ea75beb7e2577bca5716a671d1227594a7a9077293f326c0ec83ec60e1c1860f8de734591f76c93079010606b62b5d3a8788ceef1941fcb89605da9fc1c118b6cb5958a06011ce6b3fe965eca4c4658ba1eff611ee59125fde0b838666e0ffa61939a3011464fe0b41b677bdbf15833e210643ad1568907147a75bbb7801ad2ea19e24f42008a0de5419ccfe5e5cf7b5d4a67bc44bdfcaa681acb50d7e2db3b0eac76907a9a2e7e2e7c4ec7e6d2f5a19aa31f583899cc2d5e03521a231c4f7299a089de5a6e021466f6e7da0f149b9a0f55363290a2a7ca3ea8e7a5e31821dc24df46347258c5b958ab39c3f4ec1443c6b3077f3ac73557b6e081d433eec6eb95603719ba1ec074a8afb051be602497a3be4f19b57ac3734f79af4257b0f369bf52f2dd21cf579ad17cba0363509f5c1d4727f0aba415ac90d45870aad3274a03c6de002157db145351e107ab9c18a5930926ee15aff08e80ec7205a517f9e492dbe014d1b984f862686214ee45c55f72ce1b5f060f67c5e0565fecd73945c690772b285136ce4a78a84ad994de7c88fc9b49cc78d08a208c2e1cbce1ba5b523c75ad40c0f335a2d7bc697bdda03df0e4009d1d294763259095e4079f8a2dbba286436abae27ec375d855917db879682f8b4fced076172163ac8ab99e523aea9a7821a26e2df1e32d524
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134233);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3169");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42633");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fpwr-cmdinj");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco FXOS Software CLI Command Injection Vulnerability (cisco-sa-20200226-fpwr-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower 
  Extensible Operating System (FXOS) is affected by a command injection vulnerability in its command line interface 
  component due to insufficient validation of arguments passed to a specific command. An authenticated, local attacker 
  can exploit this, by issuing specially crafted commands to an affected host, to execute arbitrary commands as root
  on the host. 

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fpwr-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f935994d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42633");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvo42633");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');
product_info['model'] = product_info['Model'];

if( isnull(product_info['model']) || product_info['model'] !~ "^(41|93)[0-9]{2}$" )
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '2.2',  'fix_ver': '2.2.2.97'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.144'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.234'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo42633',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
