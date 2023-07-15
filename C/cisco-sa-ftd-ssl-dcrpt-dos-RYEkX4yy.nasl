#TRUSTED 992f02933cf12b3071873d1ae56253eca284a61368004711ac6e172f38ceebce1377c683020856e8b9ebafc41b29837a337a659bfa0fd89576613bd3043e3ac630480309e9580fc6f32ed0aedc4ac08b99942be96c7f3c95efd6d8c4a0a9369d36007cee61e35be1800e6c28e4c1934a0be23a826ae343554a5d31c2390abc974869476601ffe354d542889ac2488bd1a1c8ef67cb270e200f7f772a15691e67116edfdf05f3089215a36683628be482acd283eff6434160ee3b14369a43e3d4e0266e407924bbbe3193d022ca534febd54cf8a93ff0d38588701f5c07ee05af1fb3ce1f8dec8525ed2ba059d7d14204f94f980bcda9d4d667caed9898f185a7070096db0e1dab58b3ca88062b7bf2ddd4aa7fd1be5c9491c2e4e4b872838cc0593f1840f39efb47fd766d468180554eb1e60965420ae2bd62fe31320da5ab6dc1145b346c56dc33a7b93a8eedd204f2bd6975eabd314b0cc4dbead77bc1999f6c2dee5edfec3e393f71cf20f607f4d75d63c104d4fc43b47ccef1c64d7a3fd702b283dfe0ec210b83c20cbad4e6bca9adb8a4a634ba769133f9f13ee3dae82b9e2e408db610c9163a698938c9d01639ba3736926a69f4634d60e569265d0f9021e1be8b8b869f6f4069b1433ec6e12e0e5cd5ec3c8e09181745b650712e50e5f86e9ade8dd367cff191f88a62227b0428848f04e7f88d865f40ac519e6d8ea6
#TRUST-RSA-SHA256 18915a0b0568eb803a88e8f644bfdc4133eafcefda68d108d673059862c3b2045fc2c5a090e23c7bd0a1067d769ccd3981d3d77ce0a82fb0ad8cd9a3d4e4c1c55f881ea4290565971dac02678fdb2c33b8ad9bc6d16e5e3236cbe6ffb12534261793549a9350c952c9e9578df05fed28361a90429e115154e84db4b84e6db4daf2b9e9c994fb02a00fba1cc0bafbbcca6e354f8a601631abc65c71a86b0225a32a9a40beefc70a2c10470a192779c501c6160d7886d837df0023d5377635f2a6041b348e8c4c510e8e04ac0d278a2126b651720ade0e68cc54cb87d2cc3fe6fcf45807c2c500f8856c8bfcaa7cc8f9ef1490812d7a4847e56dd1772317e733772d536d85c23b16810d2662915c3924f50d6539c48a934112e9cc5afc296d15a8d66a8fc819e4f695e089b4f62df574b66004b0b9e0055b1e08e79e2ce571ff874f5bff87ddffaf076ab7eceaa6f3a81dcd840d4185bc25b6e33050067f34dff1ced75b157058e4ed986daf3dc1e46720f73c5d4e4f2981c7ec99ed7eadcbdc26db9451ba4214f06f440954879e9a5312798d8610d6d077d6da58b354be2a45ff68b5f00a15d21c845b427d908edffd66c784df52bb5a0e1a0f31aa6e98783adaf954eef4c466dab4dcdac8d26049346cf50dc9372e2cc1ad6553ebb9d7f4f3151c40995eb0c76036ef937e7d3c870927139b0b9aa07f4370a31f5e54577ed45a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149465);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3562");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56802");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-ssl-dcrpt-dos-RYEkX4yy");

  script_name(english:"Cisco Firepower 2100 Series SSL/TLS Inspection DoS (cisco-sa-ftd-ssl-dcrpt-dos-RYEkX4yy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the SSL/TLS inspection of Cisco Firepower Threat Defense (FTD) Software for 
Cisco Firepower 2100 Series firewalls is affected by denial of service vulnerability due to improper input validation 
for certain fields of specific SSL/TLS messages. An unauthenticated, remote attacker can exploit this by sending a 
malformed SSL/TLS message through an affected device. A successful exploit could allow the attacker to cause the 
affected device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-ssl-dcrpt-dos-RYEkX4yy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4ad2b95");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs56802");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs56802");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
    
# Vulnerable model list Cisco Firepower 2100 Series firewalls FPR-2100
var model = product_info.model;

if (empty_or_null(model))
  model = get_kb_item('installed_sw/Cisco Firepower Threat Defense/Lw$$/Chassis Model Number');

if (model !~ '(FPR-?|Firepower )21')
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [{'min_ver' : '6.3.0',  'fix_ver' : '6.6.0'}];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var workarounds, workaround_params, extra, cmds;

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');
  workarounds = make_list();
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  #note the pattern is inverse matching
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['ssl-policy-config'];
  cmds = make_list('show ssl-policy-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs56802',
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
 