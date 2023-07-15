#TRUSTED 9c716d4e473c06efd4a1477317e45db1dc20e90c925345f64756ffd2d42b0305729cfc876dc5b0c870e30e49699d8772144eba1a9a8c07efc5a5ea23e506b1e84fc2490b902a6ded662c8f27bc8857947143b29f5ae3bbc7479a38aa5f490db8d941a6b49e383f124dd452b5d2c2c77d3bd269645e2a30a393168f00dedc18b7a94a4e49499d1c2bec80dec9bb16e7627912ced5beeee8f894eff3fd593e51c59b64169983a91a728071125c53783d62bb5563c2f836a9cdb0e82f8ea8118b074f2be04fac24e12578108093f67e078cd5bcfc970009807caa227975628676df4f22372919191cb005083c9995eacdc2585cdacb7dfed530b593df46bc17b2a8cee60d58a063ed808a7b249d533880ae81c9cc53a19b57d2c109760dbb3ef36577e2359872a50e95b6ba97c8ad9770c33bdbb80369db476abf75f8d07d5acbff31a4ce189fa7e5ab90ad4ba2860d88b420102489dbbb2cd950b1e761b38514521b4fb435c110b21c9a5038f88e33b07a927b615e9362e52a3e7eb9ec8efbbe923bbf9e9371c5f9ef3e3536aaaa2ee88ef38091d3a1b0b506069de89cc99ce44415cfd8bd726ae0fa93e947fa0bf70787951edc6355ba08c6cb881da14d1c2ecd5ca03cd1848535f23cea458477b95be7ea31e6e60e8556cb12f845d1ce2573a0d7770d46a855499dc488236dc2f9e313365c9f69f93bf10a2f51df2ea724bc5d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133046);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2019-12695");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp33341");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-xss");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Firepower Threat Defense Software WebVPN XSS (cisco-sa-20191002-asa-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Clientless SSL VPN (WebVPN) portal of Cisco Firepower Threat Defense Software (FTD) allows an
unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the web-based
management interface of an affected device. The vulnerability is due to insufficient validation of user-supplied input
by the web-based management interface of an affected device. An attacker can this vulnerability by persuading a user of
the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code
in the context of the interface or allow the attacker to access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf358a6d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp33341");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp33341");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.2.3.15'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.0.5'},
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.6'}
];

is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    workarounds = make_list();
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn']);
  cmds = make_list('show running-config');
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp33341',
  'xss'      , TRUE,
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
