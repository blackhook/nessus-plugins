#TRUSTED 4d399b40a47afa7fc73588f66a104baed216a29033cdc0d303f2e555cef3495e30d45f2f1ff2799e852c70dc07ae1596896f3f852e2d4f3ab3a2abf5706f91784bcf56962c21db2fbf44f022c9368ecf639053d1e60352dd05d798e2d912ebfba189ed9f49b0af0bdfa29fe98237cee9d1c7efeb7407f6b26dba4a0a849f41653bba5344bb4d1e36db25c22ac16c639c1e99c683f63c083757b0b003dc88ab80f9feac1290da2065027ce4e2da59dd94eb07aef5d690ce2cb2025b15c730487ff07aad29f48e00a3783d37292989006067f787ffd517ef34337e6473860fd441cc8bf5c6fd30c114db17fc85c7e202a0fbe3ca283c06bc19f661818dfae3925e43d0765c89eebcf82426bbdaa2168cb7528c779eb07e19aac38f3fe17544ace3d11e8791baf4f322284b46bd071010c6b217287e09aafb83d28a2b151934d6a3db19751e4efeef8b4ca66e67430472a2606a36609963e5ec48b4752ae8cf8b7fc8e3b4f9a4c099eba82304b1610150b4b5f86814ba0c4a69a469bf689c726a9c5a4b810aa85c8fd3456c60a150ec9ee79447c27c47c7708bc4fc61575b26c9dc171f32f4fb864e923c486423a561523a6c2dfbf4a2a727bba25acbec39a13bbd2d763c12acce1a340fe7b2a820c1556df0e3c14a9a2648b7b9df8c5c750f404a50c90eb51e1b5eb338a5705f8e21e962a8852bcb5b588884ed7a66601377da6b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135291);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/13");

  script_cve_id("CVE-2019-12694");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo45799");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-ftd-cmdinj");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Firepower Threat Defense Software Command Injection Vulnerability (cisco-sa-20191002-ftd-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in Cisco Firepower Threat Defense due to insufficient input validation. An
authenticated, local attacker can exploit this, via executing a specific CLI command that includes crafted arguments,
to execute arbitrary commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-ftd-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a585265");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo45799");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo45799");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12694");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.3.0.5'},
  {'min_ver' : '6.4', 'fix_ver' : '6.4.0.4'}
];
workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo45799'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
