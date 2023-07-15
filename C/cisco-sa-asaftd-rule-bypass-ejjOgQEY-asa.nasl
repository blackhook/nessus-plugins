#TRUSTED 548a106c73e0b69af6c19550579d085437a2fffea3c4566829c28da080a30a260f7f52ec7150afe07b074ae5f0bfaaf40e3ea8ff233032e265caaf63b3bc2b2be3fef5e7d32366abce95c581cf4a8bab38bdbf9e01f66500a015807237cb3fc421200a748097a0e299e6b0bdfd8f831e72743dd1cd797f49063700ea25ebc6059a3a6e0ff33e92378fe0968773e23cdb1a830373a351841fe714d2a9fa96e482fee723e9b35526d890ae4c1611b7062dd2d9f14e9c3efda88f532d559684e8fa8cc423e363dc17e4f64e4b67f03353e90470a3c2d41d638724f6e748c7fe4cbc7ba963451c067ee2e0e25b7afecde6b5985a5699cba688fc5cac56fd1f276aa76475b2cff69d5bab3afd4596cd17e68d9e1e2baba7d92600e14f2c8fc3fcc056f1957e069ccbf01e527f9e5a0b8daf56a8f3dd6ba8e60ecfd0f289bd2027bd03b8ed4767a4b1d9e6377e7ed3495a3eb0978d32f9ed098fc385782447f8afaf9a4fac44619f6339a4d9e0f772773c817012172b1f9c662019d0e95074eb4c702a1357d532767845fef1fd2c3bb6cc2f14e022ea2d2d5daf01042bde966212d0eca7d830021ac1e9cfcf1e7387054339e39eb871afbffa193454777a127178793c58ea26b93e00f8ec90f182444e82b22579a15ee0d277ff41330ec51a7417311fbd3e8b8bb9123d39153200d6ded50ed7a7ddcbc6c3dea4c1fe34655326d72c18
#TRUST-RSA-SHA256 74b5add2f22c39b616fa2329e5d52b3371e9e209a47051f12e491180f69eb3d2ad658d51ae9ce456138d6b70a232fb65338b08326eb6f16943a213b6bdd5e6b1e6f7e27db67a4000af1d495dfd62c83f357d0143de8f70b95796a0d499a533b4a433700e5f294188f8caa9466c9f227f11c340d0838bdddd7f20b3624a963f95ddbd96ea36192ed8b1600f4a11fc204de3a3c8bf6a5b4e07f43f5c248825b214afe83681564f58676dd092624fb0275eb0bb667e0423f7e6532120551c86f6035bdd790953bca2ab0fdd5f3ed88c4f9382de58eee8650c809437bde1633bd96b81d22d95f9a2f3e73df617f07dd249c40e421e2f120a955a1a7dd5445f68cad5ae832488081990c391de800266b70014a0fff95c36940e2466a870ee1b1b175d48ff9d393ed998f0d8c1dd2f9d6949ecd155fac9a7b6159291b8763c2e5ffeb89de797b78c4b4633400b5f9392aebbabbeec594e8681e3d60b83d93eb583fe844cfe383902649a7357ae81e0a3f400ec7f813984dd01d5085aba2514ce316b6dd3ea38b6c4a833e9674f645942f7bdd30c34a1697c1c4ca1ef17dcda1759703553ad740f6112d329ef5494e06d99418978df3c4cad976515df8565b018c030eaf54044533dffe2f0405706e640aafea9dd5694c83b60c580b24b71cccfb9bbd156251d5cf4b7bc31e72a27fe4ab472422cc1841c488753a2cb67a556453a61a2
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154828);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-34787");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx47895");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-rule-bypass-ejjOgQEY");
  script_xref(name:"IAVA", value:"2021-A-0526-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Identity-Based Rule Bypass (cisco-sa-asaftd-rule-bypass-ejjOgQEY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability. Please see the included Cisco
BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-rule-bypass-ejjOgQEY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7905c3c5");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx47895");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx47895");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34787");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(183);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.40'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.25'},
  {'min_ver': '9.13', 'fix_ver': '9.14.3.1'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.17'},
  {'min_ver': '9.16', 'fix_ver': '9.16.1.28'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx47895',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
