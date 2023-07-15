#TRUSTED 25ae25a0764ab0dc266b7f6bf3f71d82b51f99eacdc33d2a2085aa60e346f32676867b8babda2d544a140b52ebf504c64be8a274138c2af64bcff2f2e4330a0762b2614d5bf6f5f84ef480fe560d2b7a6b7edc5a6f333c5c360583357129a1969333ee25aed702611b5fde028aa6074433fa923017426e5cd78886d792db626263d90f2cd848a77624ddb99017b1c01e993b5781c146f6299de46c942f93315b974cbc2a22d3bed3e8cf6294a55c29d615e941af08121a6dcf171c25e453b93bea9731081f7667f906be727ab7aebb84e226924f15a8251ff7ed76707bea5f3a114abd48dba09308f7f18187d25fa1becec4493d936ea7702fa58402d7519f3b41483ca9649b55e1f7acf557f44ab8525f7a514ad2bfc6f58249377502aa74d07130a7fce2e766fde1762a8d1a941b076ad3760545a4e11491bcf5e3ad78704f68625403be992f46b984cf376dcad20b55030bfa37b493c1e0b9e71f38e2796eb3e48c0025266a1026d9191cc09678f5d00c2c9ea27989b338f2015279dc4b523bd6d4f32b9f46279089bf727b245ce05e2dbe5b610fc6668f6bf4302adc3cd38c22722f6198c6664be0dbb678e6624a0156c922bb27d189c8381d406bf7c71942f2a45d8957799dc14415b517060f56827c97a168f830d9e41176f5ad1e79703f601d5b8868a2b443148d025f4b770f9cbf183c11e7feb61e26f22dba4a3576
#TRUST-RSA-SHA256 8da5fb89da187a0369600da718e1a46c0530a4697152c4ee33a1f729defdce297a235441f7865059f01371108d737c32d296e3223b2a3d21e3ef40705e32aad194f55f68357239478ab90a0a6a0b126632e2a9f6ac0683f5317fa92052f6717b0d15c1f322f5b293f916bbf5644e27b4e3691fbe6f3cb806b68d83dc176b78e5f756b467165ae6bfce241e05ea561688669221b6b384e46f9ab7baebdcf324e314e17cfec8c6cd327acc70a35782ba56604ef9a802be872386ed221c16014191060f5843cbf1c33998b6b51208f4687e317b4b64a864e118ef0a9073f718e34a64255a2e674fedec26e7d2dcb6712064a1063bf840958ecca8c83fc974bce5190782ac1c45d74b6920bac38b99bead32f26b9c70f59971d70ca6ce32e16c7e6a72f66dbcd4d5f548d617a44aabe1adc4d25d1f0a7360023c5d2a5312cbed4467b6d63c32d726662066d75fbfc3993ae5b44b32a4f8eaf6f20d8c73a3d9b8e91dfed269406fc4472419ea96b0f4430deb57c2af723c3a1886621d989d4a9eff990078fb3bd2cfddbfca5411545b6b362f7a0b8019b4adacfd9f1b3a462f532fafbaf44f9afcdd112929f553e9a14fc0752e2dd49eeba3607258ea4e82ebc35240416d17880ecf11a3b7619f301fd6c6205b78c4ed3a9942498c0c1d67a6ef2316030a710856157c17132a9bd8d51ecf02544473c50fbdc7f15d267227a188890f
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160479);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa33898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ssl-vpn-heap-zLX3FdX");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Clientless SSL VPN Heap Overflow (cisco-sa-asa-ssl-vpn-heap-zLX3FdX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by an heap overflow condition in
the handler for HTTP authentication resources accessed through the Clientless SSL VPN portal which
allows an authenticated, remote attacker to cause a denial of service condition or obtain portions of
process memory from the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssl-vpn-heap-zLX3FdX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71203eea");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa33898");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa33898");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.44'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.38'},
  {'min_ver': '9.13', 'fix_ver': '9.14.4'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.21'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.14'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.7'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);

var workaround_params = [
  WORKAROUND_CONFIG['ssl_vpn'],
  WORKAROUND_CONFIG['ssl_clientless'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa33898',
  'cmds'    , make_list('show running-config', 'show running-config all group-policy')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
