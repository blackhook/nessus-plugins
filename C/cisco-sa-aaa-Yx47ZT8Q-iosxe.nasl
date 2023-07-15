#TRUSTED 60ecdf0f016248f42db5f690a7f267b4c97b842b4f0bc29c263a62e15b49b62c6b47c111723f93cb79fe37d956533cd39141dfe1b252339000b4ab6128fa6f05b3571b978fcd6fd7961346479cf996cc0285bf26b74df83ee94e18fad74f877df2c9459457323f877b60519d977e2de46dc654b45440da72bdca96007decaf1efd49a7491ccdfbeb12e0bb203b5915bc694a5a0cab9a91341657e2974fd09a687a705e153b0ca5bec5141da4adf88d56007efdf4f16dacb4c360f17daac7dd2f6e475da20b22c5f4b2293514d023594abd5927b2caf93946e2211b6d37c4cdfded2977a94e4786e81e7bbe407c64afde0c31c317ad9a9d8966550635f40772e29849c339befb9fdf66b1fd1a7f282f3f3ec41643efc755438c278572ac478f30db4d4ab69ea891d6bec948e7a982fdd3cd89e16f20dcb5883f46c4dc11af277cd53f1dff617d96f0c5b71333b756267a7addd46e87b0d3c85a2ffa646fb83e55cc3f147be01e8994861e618454bc508703f11f3397a9b3467e16fb02101851b33f46603ccbbb94a54e696f6dcd2ab44556fd510a2bebe7841c7749caef77ee8eff367d361e982272ed63a5acaf667e6142acaf12a73c3a2e6a3417abe47489cd7e3cbf514388c9d30b58a7b839ac76af89c856231955ad5e35d56145e8785e1352f1664ceb00c086ebd8b269b536697f963ced95743b70d8d0bd8aa65306a505
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153895);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/02");

  script_cve_id("CVE-2021-1619");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt53563");
  script_xref(name:"IAVA", value:"2021-A-0441");
  script_xref(name:"CISCO-SA", value:"cisco-sa-aaa-Yx47ZT8Q");

  script_name(english:"Cisco IOS XE Software NETCONF RESTCONF Authentication Bypass (cisco-sa-aaa-Yx47ZT8Q)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software's authentication, authorization, and accounting (AAA) 
function is affected by a authentication bypass vulnerability. Therefore, it could allow an unauthenticated, remote 
attacker to bypass NETCONF or RESTCONF authentication and do any of the following:

Install, manipulate, or delete the configuration of an affected device Cause memory corruption that results in a 
denial of service (DoS) on an affected device This vulnerability is due to an uninitialized variable. An attacker 
could exploit this vulnerability by sending a series of NETCONF or RESTCONF requests to an affected device. A 
successful exploit could allow the attacker to use NETCONF or RESTCONF to install, manipulate, or delete the 
configuration of a network device or to corrupt memory on the device, resulting a DoS.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aaa-Yx47ZT8Q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?086551f4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt53563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt53563");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1619");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2r',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['enable_password_no_enable_secret'], 
  CISCO_WORKAROUNDS['generic_workaround']
);

var workaround_params = [
  WORKAROUND_CONFIG['aaa_authentication_login'], 
  WORKAROUND_CONFIG['netconf_or_restconf'], 
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt53563',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  require_all_workarounds:TRUE
);
