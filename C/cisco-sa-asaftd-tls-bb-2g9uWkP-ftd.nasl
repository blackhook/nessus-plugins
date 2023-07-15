#TRUSTED 726894d3fac5de28e41f29d1f911956e392aa178984a662a650846bc734ec64a5e56f8668c1cd37fca5733b9a83c732809ba2f1754d301938676c3d3ff7ac8d8dad3afc4be7cbcade49fb088bd96131d71d895a7bd07284a732c2852abd202837c973548252ae4a1812b903c210a73934c3085405224b2c7b997437edc3a0b6be50727adea18d631b36e58d716809045db4ff2f0884559e7a0a1079864312484594a3dabacc24b60524946b7c54c776b5e5e6d2e5678f7893a9a3837049c86943f848642fbbc8dba6e5ab16b7019722eb42df1479507de5e5336caa27a22b646a96eb99cfc4df52eab19afb14e1d31c2f4d10ee808a08ddf2cef1b40a4d03b0c799ee579fe1fa03a19d3ebc7aee942f6490f20ff85a97343287e2a91bcc4f883fcc245bb138437f62e1cbc34d38d088a4f26c0c8d5025f62192d8c7257614da831582713f4e813248e14e4e5eeec310000dfabf38f4ba98cb9b7848f51f4d710c9ad456160cfffc8f4addfb18c2f15e0fc0e3a1a54a0478abb87e0e157a79dd7d279e68f0e77d44f70fda68f00b09a29998eb6d8a401456090b9396ea5963fd7ba308712eefd3a99aff4698e251b7656fc5bce95e5b6dab985db0985265cfbc1c7f0f445e4ba38ce7d2c2c2157bf33544332a5fc357a22a1d40ee4a64e58c1df7ce0e5809ad14382a9fe3f2cc3463aca2eec890ccc54f1538a690dc301ed69cf
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149471);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id("CVE-2020-3585");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv13993");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-tls-bb-2g9uWkP");

  script_name(english:"Cisco Firepower Threat Defense 1000 Series Bleichenbacher Attack (cisco-sa-asaftd-tls-bb-2g9uWkP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the TLS handler of Cisco Firepower Threat Defense (FTD) Software for 
Cisco Firepower 1000 Series firewalls is affected by the Bleichenbacher attack vulnerability due to improper 
implementation of countermeasures against the Bleichenbacher attack for cipher suites that rely on RSA for key 
exchange. An unauthenticated, remote attacker can exploit this by sending crafted TLS messages to the device, which 
would act as an oracle and allow the attacker to carry out a chosen-ciphertext attack. A successful exploit could allow 
the attacker to perform cryptanalytic operations that may allow decryption of previously captured TLS sessions to the 
affected device. To exploit this vulnerability, an attacker must be able to capture TLS traffic that is in transit 
between clients and the affected device, and actively establish a considerable number of TLS connections to the affected 
device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tls-bb-2g9uWkP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c27f3ff");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv13993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv13993");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(203);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Vulnerable model list Cisco Firepower 1000 Series firewalls FPR-1000
var model = product_info.model;

if (empty_or_null(model))
  model = get_kb_item('installed_sw/Cisco Firepower Threat Defense/Lw$$/Chassis Model Number');

if (model !~ '(1[0-9]{3}|1K)')
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.10'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.0.5'},
  {'min_ver' : '6.6.0',  'fix_ver' : '6.6.1'}
];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var workarounds, extra, cmds, workaround_params;

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');

  workarounds = make_list();
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];
  cmds = make_list('show asp table socket');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv13993',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);