#TRUSTED 9826de9829ace3f4e01b1fedd44392380e243cc81443e843bbc390ae931240e71236ae6e67dfd4cfc6535ac1801f704e61a3cdd2a3fe048904ffe545ec4d21ff93417e5abb03fea0c92e6b6a0913ea078388f729a8b003486713bb9c2b7270f9f0c4f5bfcffe89c1c8521e05cda896231daad944065ac6a89b4d7a34edaf020c4f2173952daa3970034bc1c84185c1d2a11b908dea55c43239041ec16f61e660ad99431ed2c2c7c844a00b70f1e688cac8907212005698f947fdd2ce988891bba71b6d92f1287e2d476b5699ca0f7d04ec865b99802ef7c0aa9e840d996872d170387cef1607c1f7e07ace025bca914f4b39982d09bde6f72da251d15a0f39a06e24482042f1717db6fdaf4711f28e900c6b3b8b5316403b2213e8ac914493e37ed92d0c7ba98facbcd848e2f4331ac6bc5c019672d62cda26d481294ccb455557012a32fdb9c0b7a34bd4447b8219fda684efe3c3cb2f7ed07b1f64da88d2f901e4c1f867b2e2db0531a0aa293dc8d8df40b97862364ad9cbc4a9a9429dee74687ed041f8dc728d1893b1bbdf8e8a3f83eedfd2be1e346fb7303df33f325a93dbc985044ed4114ec3194001976a1c331ae31203afb0cc20e3e8c09cbdab6a9eb1f5b66d93ed9675587753802c28420b418b0ccc328e6c30682205de5d75f8d468b9608b854d8b6a437b8cf06a10a879e021de1bb49caae5e30900339ad81867
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155449);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-34783");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy55054");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-tls-decrypt-dos-BMxYjm8M");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense Software Software-Based SSL/TLS DoS (cisco-sa-ftd-tls-decrypt-dos-BMxYjm8M)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service (DoS) vulnerability in
the software-based SSL/TLS message handler due to insufficient validation of SSL/TLS messages upon decryption. An
unauthenticated, remote attacker can exploit this, by sending a crafted SSL/TLS message, in order to cause the device to
reload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tls-decrypt-dos-BMxYjm8M
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ddc29d7");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy55054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy55054");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.3.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy55054'
);

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var workarounds, workaround_params;

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');
  reporting.extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = [WORKAROUND_CONFIG['ssl-policy-config']];
  reporting.cmds = make_list('show ssl-policy-config');

  # Additional workaround for these 2 versions only
  if (ver_compare(fix:'7.0.0', ver:product_info.version, strict:FALSE) == 0 ||
      ver_compare(fix:'7.0.1', ver:product_info.version, strict:FALSE) == 0)
  {
    append_element(var:workaround_params, value:WORKAROUND_CONFIG['asa_ssl_no_dtls']);
    append_element(var:reporting.cmds, value:'show asp table socket');
  }

}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
