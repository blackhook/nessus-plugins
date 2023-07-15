#TRUSTED 44abbbc6d761a11fd02ee506d30113a3bd485d591bbfcfc098d45d6c1e9d85f0d0191c2560ad948c539c4a770c0cd1fc029df58ebb6f9d821a5558ee2afa2d523cc18c861b8098082d3af141641c42b1ee581c6a5c6122efb584d9cb4bcc53852c78998c9cd4a1b05f6affb9c6821dea31df574b2fb3ac4b194944703a1f2ec9f7e7a454c06b6963cad558a24d2d911937fc76e9b4d436944bfa69a98b01a5ce58eac5ef360fa22f049f9a145362e4000b1ca2243cb45313a962140719f23f4c49146101f0b2f2c77f0dd0284909716491e1f943bad4e1857d576bbdf6664f76dcaacf5f043de0a9ee77d8ce9975fa00e591df10f661431e0ccb25cc1e871f96625026fdd1a99655d717847b683de84b4bac5ec3d8a6db558440b065d830b8e0657b8b98ca1505ef821e3b1ef1f7456f488704173a38aaf81479c9d60565e4c481b1f181bbf2399d097d84b99f2615654156730a16a6ce9a327d02b5434c2ccf336418dc155476bc27c32b23fa1d03006a97e67c00e94fe2096ac57a47292a7fdda9733e0e1889fc715a3613890b72b1b4dd1ec4ed7b4af73f1bedaa0809be3566e1b5e4b1564f229555b7219e85b2f6a22903d7233113db40822688da56fa44b576aabe87b3f8325b9dc60c04d88a9354fe5314680e5e485edc455143546b328a55fcfa34c11c82a8c160136e2e49053c28593bec8b93f0aa4019261043738e
#TRUST-RSA-SHA256 666502ed151d0c4e38f50a4d2b313ca9e89a39f84b8b1ac91b57717c90620de6327d505b35c53de7b6686fcf0958035c9e57b83bbd4b06688e736f053ba90d6f1beca70cf0b2b316b3c412aa58ee8823b305846a4d47bc327126742bf5a28d155dca1e799e640c3ae542a78b00ce11ff83f5323a3e2adfa3246c7f7806f820fe8b1f9f9bb8b80c49632ba1167568bbb4d8ed51f70768759600a7ada4b5206b43b0a68561e59d983a6199e8b29605dfe679799bb31188692553f20ea822bf4f4340bc929c6cf22dd5d2dc00c4218f180d94bd47b64e1452b5bbaeba15ff42e7c40f19f3ff8c13c799aba2869ed136929f3f3fadc69b5eafcccd08cebac9bd856bd1e6e701a61eb79722652a5043745ef84cee056fb255c44c01fdffdbfdd20072000d539054422527c0a76bd7592d1abdce2d4712badf052ff0dd3e6d4062fa2240be08a51e5df1cf9ed1c54acd10653ebc58d617af809a111ca1b8399c869da926dfa3506154cf2e069e37fec9cb80d8a2630f5f13bac7271e4eb4edb301e8002212c127cfe1cd6d56b735a98570ee9a8c8c5f9122f9d336dd6081d0e38f0bcd6fc7c867bc29ec5b7f1d6a863cdf98d47e7966d56872a743303064e1e6e4dbfdbe3b93570549e5cd557846d3b025d9ea2f66330dd7017428c4cc5b4018ce4ab55bdabf2d6f60574b907a83dfcaaa6df993414d69494205e13f6dde405d57061e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137660);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt15163");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-info-disclose-9eJtycMB");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Information Disclosure (cisco-sa-asaftd-info-disclose-9eJtycMB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Firepower Threat Defense (FTD) Software due to the
handling of parsing of invalid URLs. An unauthenticated, remote attacker can exploit this, by sending a crafted GET
request to the web services interface, in order to retrieve memory contents, which could lead to the disclosure of
confidential information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-info-disclose-9eJtycMB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca70b7e2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt15163");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

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
  {'min_ver' : '0.0', 'fix_ver': '6.2.3.16'},
  {'min_ver' : '6.3', 'fix_ver': '6.3.0.6'},
  {'min_ver' : '6.4', 'fix_ver': '6.4.0.9'},
  {'min_ver' : '6.5', 'fix_ver': '6.5.0.5'}
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
  workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn'], CISCO_WORKAROUNDS['IKEv2_enabled']);
  cmds = make_list('show running-config');
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
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt15163',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
