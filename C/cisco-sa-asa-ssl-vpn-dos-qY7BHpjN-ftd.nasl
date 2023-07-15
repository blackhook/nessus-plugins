#TRUSTED 13f950f1fa4fd4f767efd50648802ee057f262466d2a4366937dccc16101b7eb5fcdbb7eb7c7e284ded3bbcbfa39da2990fe3ba96d165c07c1996e321df267a7dd962b5084b87b7f9db1ca4aa3095290c7987f0919b5f089c74c7d7d8f68c376b556960699dde690b01290d3f1a54ed637b4706b5b31040031925c632e298f9c51add237412c9e43ea30c3c763700a92b9b393278f0a41662c011c71d07bf24029228ac668e5362e78437487aa68dc179169cfe56f249052b311730f079c41ee00e22dac9d77b231b320ae41d2aaaf59e4eaf67aa8899706233372ba18460d3b4860f6f42fd829b12e7dc5014c1f5255c0c3b9af78638cafc74718ee7fa584e5eaface0512a677d1e5b8037f525ea3064edd3e2fa810a6e43ab88de2ca76cf2db6ff0a592ad96eb7c9d54d38d8835706fd19de190b03adcb002e38cb54429fb447028df7dddb4ae873ac1e15075ada4898ce351566c1e2d576971de7b8b8cf3016ed37cb6203ee93bd714fe37cec56b449dfaaa439f0d69a85bbf29a5e6e892596774d5efd77c1af8888873a881ea9571124563d99cdfb08b649f73708a54f37e1e6acc33b87ec88dddec11d5c6cece1a0e786e7c3d2581b68695eb313eaf9a071a793d7b17518142c7ad99d4ad3c3c4dbe5a94fc9e53a53713184cd439c6ea853c2afee3b00eb8a3591caeb9eb5cef7281664a5995f895c4f5774fe8b4af22e
#TRUST-RSA-SHA256 2d968589b803c5642007b842d188d57625a4b8f1b704bd7bf08415e7b4a6dc5ffa080162c3d1e0f11aef1819ddb03d8d22371a51b4b4cdb0e6eefff4d6a046a93afbc05be99a7f8f141ae7ddedc2a8a044f2316ff594d421fe64d2bc5fa08522d6b94250a46ff4a9b367fea1c972f7fc298415f3c80905a8e2681bfdbc852944f6ea53ecc1b44b337996a025abe1e1be0227a26e01ff9e8c401715eb997a4e0e461cb2538d5bda0d7762f36c9719bf99cef086c67849b85eb0be5e7901b1844e70e00af801444532c25842c5b77f4639d7424b8fcbbccda380f66f432c96cf5601d1388fb80f4eb27f3b617cc283f7b57500affe0339d00a33ac8357b79936acbcf3c96d0c1f5e54cb209530d918f0db473e09b15c086345a9a2801fc6a3dd7aaca706f205ba2161a0c4e7b14c763ef71fafe401b9d5425e6647df7a08829148d00a8acf51796da35c37633c5fdbe9a3d3c138fa4bac3c868b5764710534be16a2bbd013c753eb534a005300687857a9813dbca749b93a3fb27fb8e922267c740a4827fe0d2c77e8d38219ad4f053bc2a3b85f2df4b162c797e842f901f0545086afe98dbed56b60eb6bf872e9024f551e7bc9943a47115174f4231bbbc7d3e6300a21f5c38e758e69c31cb76a12048046e9518bc57a670104c7a31b8fbc78b73f8bd13b1af11dd9f23721fe6b8c6be0a0ca17edb0a33da30ccfa87bece56a18
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136917);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3196");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49481");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp93468");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ssl-vpn-dos-qY7BHpjN");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense Software SSL/TLS DoS (cisco-sa-asa-ssl-vpn-dos-qY7BHpjN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the Secure Sockets Layer (SSL)/Transport Layer Security (TLS) handler of Cisco Firepower
Threat Defense (FTD) Software due to improper resource management for inbound SSL/TLS connections. An unauthenticated,
remote attacker can exploit this, by establishing multiple SSL/TLS connections with specific conditions to the affected
device, in order to exhaust memory resources on the affected device, leading to a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssl-vpn-dos-qY7BHpjN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6420bb6e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49481");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp93468");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '6.2.3.16'},
  {'min_ver' : '6.3.0',  'fix_ver': '6.3.0.6'},
  {'min_ver' : '6.4.0',  'fix_ver': '6.4.0.9'},
  {'min_ver' : '6.5.0',  'fix_ver': '6.5.0.5'}
];

# Indicates that we've authenticated to an FTD CLI. Required for workaround check, set in
# ssh_get_info2_cisco_firepower.inc. This should always be present.
is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes. 
expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");

# This plugin needs both a workaround and hotfix check. If we can't check either of them, require paranoia to run.
if (!is_ftd_cli || !expert)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}

# Don't set workarounds or hotfixes if we can't check for these.
if (!is_ftd_cli)
{
    workarounds = make_list();
    workaround_params = make_list();
    extra = 'Note that Nessus was unable to check for workarounds or hotfixes';
}
else
{
  # Workarounds can be checked with just the FTD CLI
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];
  cmds = make_list('show asp table socket');
  # To check hotfixes, Host/Cisco/FTD_CLI/1/expert should be set to 1
  if (expert)
  {
    hotfixes['6.2.3'] = {'hotfix' : 'Hotfix_DT-6.2.3.16-3', 'ver_compare' : FALSE};
    hotfixes['6.3.0'] = {'hotfix' : 'Hotfix_AO-6.3.0.6-2', 'ver_compare' : FALSE};
    # For 6.5.0, advisory specifies the hotfix name "and later", so ver_compare is TRUE
    hotfixes['6.5.0'] = {'hotfix' : 'Hotfix_H-6.5.0.5-2', 'ver_compare' : TRUE};
  }
  else
    extra = 'Note that Nessus was unable to check for hotfixes';
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp49481, CSCvp93468',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params,
  firepower_hotfixes:hotfixes
);
