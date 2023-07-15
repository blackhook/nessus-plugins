#TRUSTED 3e76b49a8cde7826732ebd9d59fe1ddeaf777954251d7be62f0380893ff2929eca170969d1c17444e805d289c44b9a4b76146993c4bb4628ff1789db6cbe319d0b17612d7bb4ffba13afa5d85d5fd92ca808ee92508f824e6ce0026f611835d8e77f0cfa4f4b4ffd8dd0d43593e5cf81a97fe1ca1de2634e5149dc188074a12251ea4a2d726b24373e7ac21686ec021a91fc87377f342b947521e2f554cd1e5036cd1e28e58b750604748937bd62ccc3921c3615754a0b2d511b1165102740c11a31a93f38c0fac9ff59768eab897b2d9700044bc7d7d2a87d955c3c132dd2333cfa77fc504938a7b929490ae1d05dc753170cc868147366dc3ce5bc9b0a6a3365192e0f42a8d3997ad21212dda3e0a9c1e1edcdd55f2c8c04d6c2a458c8474bc82f88f7c48963f9dd11f1819cd1263f8b431ac382764cb8ea3857b4cb6441fb354ceefa363e5b98b91b787f6303c43d602f40a1c6f4d2c4719519fbad4808fdee3b700d15728d0b1ce04f8b57d80b4ba6f9d3e3e9e4bdde158b189000be01ea24fcf0db0b3de63a9bd342c3130dac30193014d875b4b5716c6dd535d53f4b598689063454280020a17ad20183d57ded68f34006bfc84434038d772c605ffbc14d6ee1975e2efcf82e623225f2b49c7892d9c15b59dd3ab86fe8f07bd18b2f562f772e5122000dde67a5aa4fc1153ccec44e315c9689be9bf4ae74583492d0c4
#TRUST-RSA-SHA256 4ce0eb767fea449e7722f6656b79d739f0ff50c1591de738e209bcf3d8b2473c0a8f1d5af950ec822f1a01c76308a16cd30bae3ae18c4e49434c7a8bacb09cb04c5c35fc0c976e3985d0e067111c81add9eb32d4e46e04f95c7e25bd71a1d091b30df6a6f5ced213fb3dc50a172d2799f49e5a013e3b71b3815a7290a5c814e7d9a7cff3cfd8a0cd0ca3e5042b2376685432ca6c6b3a71eee0afe28975409cf4bf41cf9f90603fbf249a1d299a284e5c6e9ad0f83b409b5431389e05d7f23b63bcf81aed9319728db257e9163bab10ca00dfbcb3e76c28aa6e2dd6f2d372d5f73ed895f5923c31d029c29d77f976e4f643839f0f1848d0561c7571bd92c137fc0f85e3040e6322793eccff911308f5e6a3eea3246d162d940d4107aa30011950fd17737998bc8687acf3d19b2017e5eafa1e4ab1dd271f64ca1ebd18c3e32a3c4c05d9e0e8e0652720ebc8b3955126e38464b992f0152554139cccb8d3f7269d072aee329c052a337a5978416a0251c9ed93ae455bdd605ec794871246d270bd7afcb3725c7ece3a7dd98e8eb510ba36af9329b71da581955ce25ae403dc40e777dad3a97604efb02350ddd4741c3bfde1b9a2c1dfa6e3acf1e4f820e8f6b6a4b65e664035be41ded57ce85b93b225ac37c1f6579102428f0a363148fda2f2af3108c1ea9b25f79e9580732164a53b9ab06a704bc83f609c14a85706b6cce265
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174016);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2023-20072");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc32921");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-gre-crash-p6nE5Sq5");
  script_xref(name:"IAVA", value:"2023-A-0157");

  script_name(english:"Cisco IOS XE Software Fragmented Tunnel Protocol Packet DoS (cisco-sa-ios-gre-crash-p6nE5Sq5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-gre-crash-p6nE5Sq5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5a2d2d5");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74842
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86953f38");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc32921");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc32921");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20072");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '17.9.1',
  '17.9.1a',
  '17.9.1w'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['count_tun_iosxe']];
var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwc32921',
  'cmds'    , make_list('show ip interface brief')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
