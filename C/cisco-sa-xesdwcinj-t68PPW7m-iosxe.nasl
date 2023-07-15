#TRUSTED 65e70b553739c01388a0bbbde2b1f7731287a8d40a4143da652b4a5b09a1da5b3e4ae416ebbb0bbe239c02f86e0d06d76f63cec7f89b55bda6dc162f135e4c8b7c749eb7e18f6718f340b5447e9e509ed0ba95fbd62bc5c9c3ed727c1788dc8f36aca7d97b90fde933d02b5a0c63a13f26be15995ac46c5dfe023368d198bac8cd3ae99520dc6807581ad2db1db2210ad75b9e73380513b14baef43a6da07ae5ee9f8c46a5e2befe824ea1452bf035985dc601c949d9e83c22bd7f20237bffe5fe0ba969e5bd9201bc8aa10edb55db4782cb73a31d0f3b4e833f5101eed2f93a531954ee42bd2ae7b486e8c1585203e198735c13ece3e4a2e1d3415d6e6b8392d1272b9beaf378a4791790ffa33cbad054bbc16d133c6def94b425d86516a41218b302ce4d32b52f73eaacbafd8ed0ecd28eeebfe139e98497b08282fbcd80c7a7e9575325685cf38ada48f2f6ac858968ed4bdb0fdfe66a73da7f95ecf7e09102e4116d0264e678c010c54908c6685b98f8f96370454ce3a6bb55d895cb435a9158e91f7dd6eda8391b6b1aff2230b35bf403e41f1de21a32820f2c7cd210b1cf1e1876cc33150f094213809cd4325e3263d8dbe4fc619e1b7cb8c23be60efe8d33b7289fbd6ec9a2b2a3318fbb82e2a54028ef54f4fa8d1d43d4fb9484b0f083a6cf7dc04701b8e43565f64861fd2ff86b1557371d1ba10d7ce380bd049f23
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148090);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1382");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64828");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xesdwcinj-t68PPW7m");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS XE Software SD WAN Command Injection (cisco-sa-xesdwcinj-t68PPW7m)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xesdwcinj-t68PPW7m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f7dd1e5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64828");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw64828");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1382");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.2',
  '17.3.2a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw64828',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
