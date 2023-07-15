#TRUSTED 012b837f5a161e5da51caa586e6a4b3331e3e09ef616bed900fcd40b4b44b65a8eac8334a2b5fcf94dda130af3d3716087518df3430d7579074e4f7bd85cbb9f289b4d40c0b0d145c199bb890b1d2fe74ac3244e7fdd1dda569f3475297dbc4af279a28b959738cc24a116f64f078e628c2dbcc4d5264b74e861db7a93c42c7f180a3a69f32e40b0528840e7f15bed5337e72d436c8ad7e5eb3ece38f067b1ff21ab3cbb4bf663fd471fab72a0533d2286f008fe8d673f7d76382f36026a7240788f0ec8b24b21292e69801e60d8316cbd371127d3eaa2e16d4e17534cf1f370b0718062725b11569190945059b266c41e14a25708f1642d8dcf3219c9d160f460270305b36e41db0076acc05510d9035939d6cc6f611be20e38ea604dbc7da827769a3b94750c871d506ff2ae687ac85d8d251961ff842ffbbdb72219596ccc0d797cfabb66d8af3770949c645d179822fbeff76c7e9be1fe32a805e3854c94cc5d122045179368a7000dfc00c8901c310e7338ee5ba1bb6370a0d88fd8a6b71a0536e4a946ede82f6c0f5ca00afe6159589ca07aff67d41dfda8c7d397aa9feb3d3d0bdce813def7b3788bb2a33f078536f03a7bc0717c8468e4f85452240d2ee61f679321e33f23df676ecc4db72891e51d3a979520c0600afa1785224e80305250df5faca12984477228de0c94d6d9ce4452f76f270313c958ba05506b59
#TRUST-RSA-SHA256 931345a1169fb70b8640da9232017714f0292f79d16576131293583cb5c6be890238dced55f0c078653eac9abb41e4691861a5522ab0426880ee590a3f945c6f92cd03bdae238c147d02813ec387ec6906cba6fc55dfba57d6e468b0cbf6b80daf7e6d5c527a4c0d25434d459ee91f7e5d584cb2b3505419a9958435b347d9d330988bc1c61b38cd3356edca10c46f87ac17fd3f34be1f3df6f4f12208d2fb105709b7bd60b06acad176c1c19c1a44b3d69dceb2f3c92ec82c048dcbf8f650d610b253ee3157b77903f3a1ae767be62ca323a16fd6ebaf1a38852ded368b6c17c46602f29db11e9c1567c140b0db2cc15dc380f636f8a82bbef4af1956d08277493b4090745c4b56f0da6a978cd010b136ed7cf27000374e8938fb049d95f75c3e062feb1446658c4d1889c5fe123081d01184aeb361c05aa8430e87cfade38b6ea81ac6672ef03e164060516ce00432734ff939f284e0a1044e659a22385165f88f299fc27dd543200bf7fef47f84d771d6b5bdb65972d0e2faa0ddb29882dfafa3fe86e358c4df8322c35d563c9b5c2201d32c53a59de9ba15649ab4a547cb1eff22f40714f718486c27a0e1faeaf51ede9ad918ac1f5ef42a732dc1a4c2f228c9829fb2699523da0da1b71bc4fb354a1f6209fb24ed3d2c2ea212bdaa2f7f260365d2012d1e221b1ef1a541ff1be8a8e9e8ed8d3cbc34de37293e37abca3c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138893);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3298");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50459");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-ospf-dos-RhMQY8qx");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Software DoS (cisco-sa-asa-ftd-ospf-dos-RhMQY8qx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) is affected by a vulnerability 
in the Open Shortest Path First (OSPF) implementation. An unauthenticated, remote attacker 
can exploit this by sending malformed packets to cause the device to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ospf-dos-RhMQY8qx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de2dc268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50459");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs50459.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3298");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

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
  {'min_ver' : '6.2.3',  'fix_ver' : '6.2.3.16'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.9'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.0.5'}
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
  workaround_params = WORKAROUND_CONFIG['asa_ospf'];
  cmds = make_list('show ospf');
  
  # To check hotfixes, Host/Cisco/FTD_CLI/1/expert should be set to 1
  if (expert)
  {
    hotfixes['6.2.3'] = {'hotfix' : 'Hotfix_DT-6.2.3.16-3', 'ver_compare' : FALSE};
    hotfixes['6.3.0'] = {'hotfix' : 'Hotfix_AO-6.3.0.6-2', 'ver_compare' : FALSE};
    hotfixes['6.5.0'] = {'hotfix' : 'Hotfix_H-6.5.0.5-2', 'ver_compare' : TRUE};
  }
  else
    extra = 'Note that Nessus was unable to check for hotfixes';
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50459'  
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
