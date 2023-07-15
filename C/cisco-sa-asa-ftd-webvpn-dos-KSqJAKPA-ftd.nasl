#TRUSTED 2c0dd522a37e37cd46c54b81bde8e9c473009d13b04bcd8325fc4859a8d78b28c146fd1e5377a086b22d40defc575e66ba63491ee22c1c6002a7303086cd6d0a62df1b1f7fd49be74be65938e3917a21cad3c83aed45de552721029a47d8b80b38f69ed39c3580ed8c90571c656ee2232a29f33feab8de2cbac3c4f00ac389954889a17e35b3c40b17d0e83fd1e612ddf00a0eb68dadb1a1912e316849453438e6b163353182f0dbacdfef2f9bc56dcb4bfd3a2aadef92330be163309654682ea32b93f570b596d6bdf876ac221ade76ed516888bdf0e9509e47a8d75e700e97edb98a5eae4a3eda0336fbe9d7382cd105b3d8c2212e35f01064b2fe08dc64abe44a21635ce0e6a4fe5c48d03957ef6553adc559fb4a443128b034463e555507c6b52651fafbc3e5f0fab47d88b70549550977acbac9e39f39aa50c4abb3e3111834d62be227d5388faa11514d98525974ba74ec757b7702702030fc2e4c6e2f1a4615464031a62c974c0441e8937e912edfdab21d79acb8905c574cb39d96cb1da80ce4517a6cea5d9a01476881fd39c931a6b8cba3171b0910fbb5c55cd9860618cd3552900591ce2809688efcf04b22a99ed7fa6578cf46155c9bff5692c6de5996101021bf3f12765980228e392aa56478ba2a865dbc55c50239e0c3efbdfa2786b884c7f00b76d0abf4ecf05996893cdd9995d22a925b5b5fee1b9b8f3b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154725);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2021-1573", "CVE-2021-34704", "CVE-2021-40118");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy36910");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy58278");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy89144");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asafdt-webvpn-dos-KSqJAKPA");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Multiple DoS (cisco-sa-asafdt-webvpn-dos-KSqJAKPA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by multiple vulnerabilities.

  - Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software
    and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to
    trigger a denial of service (DoS) condition. These vulnerabilities are due to improper input validation
    when parsing HTTPS requests. An attacker could exploit these vulnerabilities by sending a malicious HTTPS
    request to an affected device. A successful exploit could allow the attacker to cause the device to
    reload, resulting in a DoS condition. (CVE-2021-40118)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asafdt-webvpn-dos-KSqJAKPA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47a2b253");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy36910");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy58278");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy89144");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy36910, CSCvy58278, CSCvy89144");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40118");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 234, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

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
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.1'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];

var workarounds, extra, cmds;
var is_ftd_cli = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);
  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy36910, CSCvy58278, CSCvy89144'
);

if (!empty_or_null(extra))
  reporting['extra'] = extra;

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
