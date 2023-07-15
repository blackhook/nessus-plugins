#TRUSTED 1ba518aea00b9b1cb800574fa542a28ed8deb5390d34ff63290fd6dec841fd03e74fd47815e9406109d877e19c537009bdcedccd56f8c78cb3dc605cc5849ba90224d574fd2cf741323f8323711f7e60649832b83399020ce0233febcad4b6ce9fcb6a7fdc65466d68c7090ec4cf939aec7d0c1301e736b6e8712b36a5ad9dc14ba959e5d53cb35a87fde68641e0481f435b659f6293fccaceadf12ade1efab82b965a7cd4483780f841f7f4839a59707a2dd0ec7064144b469d514c7a8bf21d3007720132b83078305f00f90027c79fa06e3a08364fa90c9f4e6430b07a94c99cc3b393ad21949b45736db1b52d26fecedf457c3d38449d22ee2d86edf4f94a346e5b1511d03816540f2e8867a438e03870858988a8c5de9823ff9d18b9304cc2849faaca46ca0596885d8fa147fe3c5605ca6efb4906e7c1885b9490ff297ab4f01f4e21a5a8ebe1c247b591aba094b93e350f77ed1e0232b62de643d392d74131d851c76ae1c6c5d74a159e7f62877e30e3bb3b456d61f99f92b2d832540054bebc66ddce06f757bf59cf9eff6d0f061e60dec87ccdee3e2403ca2fdcfd90c5316d44bfb6a785d68671513b58cdb94d15e42c6be42b1de3a4ebbd2f025207ca5cf702155bd772faba0633bbd47381f90e6c2419a155f2a3e1045c909c37e41bffdbd0cc16074a41d0620fed2e6e414f85f635b162d859ff2e4c67204b97d1
#TRUST-RSA-SHA256 7033ccde1c5b4b16264af91a8dcbe1361888828f710b8bc16336bfdc9c4906e32ba7df188c3866f54116da54f8ccdae41f3f96179de896f40844bab3ab242ae6086ea192fa06a003dbc5b18768ec8d32f836a37438135d80ae631a9f300095fa1c84448594159bb7ec4ed76366b61efc0db1b29cb29babfea72f513f42fd1d26fb60e6f51c692562e65e3fc2f4112069eb5194f11959746d499784a209b05ab7bd9882c40233478df07f245a0607d7d668885ec4538f000b4769ef89c7ae2ecf23f16deb7e8331bb215f049160f30af334cbabbac36942e447683c2615215175834ffb47905cf38e5dd33f025cdbf57a028662977e3e4a63363603f3a533f856c340e3635f93376dee075c90fa5011b9391166d4d56f97c2629c19120bfa819502ac31a467e16cf213ef888ab5b6e31e6753e38b50d6f57b1a40becc875674ff765d4641a5b6dfe15e9a1c975797ccf82963259e5e693d7da4b516791d1283b259024f8a1128c95b6db018dd8e5ce5451c5d17057cfdfc3791343e359e4ead7fb4838912c1f345436e64711e60daa2c2498cc940019239ca39e684bf3de4f068d636440bcf5ea78089cd5ac6f04aebe21e71c756df33a27feea198d98e14255825cbce347be250b1dcf9542b6a282bb9c667a4cb63f0233c8500b0278332c81346454bb7fdd4d3884201540927f778fa59b9e063455ba6fb8869992faf1ef3fc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136915);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3187");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr55825");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-path-JE3azWw43");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Path Traversal (cisco-sa-asaftd-path-JE3azWw43)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Firepower Threat Defense (FTD) Software due to a lack of
proper input validation of the HTTP URL. An unauthenticated, remote attacker can exploit this, by sending a crafted
HTTP request containing directory traversal character sequences, in order to view or delete arbitrary files on the
targeted system within the web services file system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e0745c0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr55825");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3187");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  {'min_ver' : '6.4.0',  'fix_ver': '6.4.0.8'},
  {'min_ver' : '6.5.0',  'fix_ver': '6.5.0.4'}
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
    hotfixes['6.2.3'] = {'hotfix' : 'Hotfix_DT-6.2.3.16-3', 'ver_compare' : FALSE};
    hotfixes['6.3.0'] = {'hotfix' : 'Hotfix_AO-6.3.0.6-2', 'ver_compare' : FALSE};
  }
  else
    extra = 'Note that Nessus was unable to check for hotfixes';
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr55825',
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

