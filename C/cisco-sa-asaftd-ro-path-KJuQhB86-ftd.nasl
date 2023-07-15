#TRUSTED 2e599601a30f98ab84fb81d29a6b0918dc6948fb6712fcc2f2f366b6182eb8687d980e91dc885948014b4a3c33f325e70d97b70f9678fc56f2de93dd8b89e8745ea2323b8341989af886a56da6143cc63710adf44c574107228447f49a42d393c90f71fbcc1f536b1e76a076364bf8af98ad1150c87828128db5622026fe683e6de7fae8c6d1363ed8715eae3e347d13857a2de657ee50c7b2697817703d7dab2e16ccce9dcf296d5fba9a69861309408a5d3f3d45b189050dd433e71fa0d90fceee74ef2759dcc935d7dae3a07022147babeb188487a632a0ca4d12854b564927c940f5222a7b0d814592411361ed1eb0ee1d7def0769474a1f81723cf33b6a36c6bc4089d732a907a43eac760d2a46f1bf4b8fc226b40c9fbe7cf6ce21e1514761ee539fee15de355cf6ad86958f8cbca5e3f00a0ea84b86a9dfe5be561588f0a1888b2d5675e08ffa9cff750fef2e33030ab4f02b48280d86cd5994fc4d54085f490f1a428034736edddb1248720f7bab5fd12ab2a2509dcd18e049befa4bf4a0869efda81246987475f6efecd4a6e60e5cb6f3bd52b49f89d5add7d83676cc4ac8e6c6207c26db91ba3516ef0e3911b5b6665d24e75a524eec021fbd4b0663f4bdb7bbe00ae55e0887b7ab6e9a9bb75f4a7a19100fb4a1ce52843cb6ddbea713392f807fa9c91b977f47d0d4ccec25fd9514cef4e50967c307c626d3dc3b
#TRUST-RSA-SHA256 67484e84b785a98e7b69a9c0c8d3db4f6785cfe8f264155f56afd242df4bc6312d5e9b8cc77eb1fad52a80f46b11ec1ce136f232be3cc710403ae8b312954f4bdfd277c01953c23f264a671ebe4663a2d1a295c2e22b264b8c609c3e1c9c3c84638369e3cc3cef0a223a9c26502710d2c997a753b3afed2bbf8fa6916a1781bd96d5dbe6f1bdf6f071e36c0ca2587cdc49441c66d39e8fe2c9c8d5b6d74880acd72c951d0aefe695020617461148e966824705e3da8cdab046e7752271055d924060c0ee4009367bc0bc687e80fef270cf8cec0c89761ab4aaac5956201e6d5f0ebb4a841bfc47f209922d33c3500c80eabaa878c8f9424051197fafdd19a00b0a39c90dda8eee826f00e51a5910130248553d4435f4ad0a24cae6be22ec349b888564be98e58027a3db6f35aa26f8b94bec90faaa406a4fe0fb529acaf46b3c6267817cd7b9b9e6e129fd9ee9e0f2c1916ace9609d9676989c868d2441eb724d003d9e9019588c686fc682c57a665215c30ad9664362eda323341ef415942b86d05d101b425345b850b94ef6d3558e9ddc5236e3c8ec3b1d9c629136e6253ed60b93133cfd2f3ef19844668b04850df66cbe3c5c7d3c2d77df9dc2cb0b37225bef69cdd5a64c60bc22bfbd219bad4db4fbebba5f9adf8b9766e11390f51ea6156b02354fda7a89f671872c91ab660857fca3257873750cfd2cc76931831e17f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138895);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-3452");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt03598");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ro-path-KJuQhB86");
  script_xref(name:"IAVA", value:"2020-A-0338-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0060");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Read-Only Path Traversal (cisco-sa-asaftd-ro-path-KJuQhB86)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Firepower Threat Defense (FTD) Software. An
unauthenticated, remote attacker can exploit this, by sending a crafted HTTP request containing directory traversal
character sequences to an affected device, in order to read sensitive files on the targeted system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f081787");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt03598");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3452");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/22");
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
  {'min_ver' : '6.2.2',  'fix_ver': '6.2.3.16'},
  {'min_ver' : '6.3.0',  'fix_ver': '6.3.0.6'},
  {'min_ver' : '6.4.0',  'fix_ver': '6.4.0.10'},
  {'min_ver' : '6.5.0',  'fix_ver': '6.5.0.5'},
  {'min_ver' : '6.6.0',  'fix_ver': '6.6.0.1'},
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
    extra = 'Note that Nessus was unable to check for workarounds or hotfixes';
}
else
{
  # Workarounds can be checked with just the FTD CLI
  workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);
  cmds = make_list('show running-config');
  # To check hotfixes, Host/Cisco/FTD_CLI/1/expert should be set to 1
  if (expert)
  {
    hotfixes['6.3.0'] = {'hotfix' : 'Hotfix_AV-6.3.0.6-3', 'ver_compare' : FALSE};
    hotfixes['6.4.0'] = {'hotfix' : 'Hotfix_BM-6.4.0.10-2', 'ver_compare' : FALSE};
    hotfixes['6.5.0'] = {'hotfix' : 'Hotfix_O-6.5.0.5-3', 'ver_compare' : FALSE};
  }
  else
    extra = 'Note that Nessus was unable to check for hotfixes';
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt03598',
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
  firepower_hotfixes:hotfixes
);

