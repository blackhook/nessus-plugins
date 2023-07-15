#TRUSTED 5984f01e748935602f770c5129d7454445371421813eba311730267bef9c98c7c2717108a72e0272c68000c313f104b70b25dd92bae501784442daf9f19e5020d56577ce24bd43d72b5ad1dcdf4054d11051ca5dd4724f0c41fe49834d1e7a32158a470963f138e8fd1140e023d34379cb46bd924e4551dd25fff397b3905aec757ee69e5b7673e417b69c77e63d7854ec6d2b1987239189a1d44172e741e5d457a8e6d745c625c21555f90a11dbd990d8e3c6fd63486eebd37c5ea60ebb54f0ff853e2aea8adc003119e99f2d7ee68e5dded3dac1c11bbcfdd3559f6147a5f2160837b12529e1f7bb0e0aceba354bfccc0db9417a0ae2b43d56dc086d69f3c62d4ba0937c57d176ecfd5e4ac77dcc5ee2d73743474bca07203c3861bde82b1928fb9726f38f410c811a84b0dfb4ebaef0ce16a481d18317791b5d2b67ea454ddb056a08727f39571600b7f902461e5be1795bc9081d49c79462a22abca8b8b8b205f6a5ed01e96b2dc7f4aad536db57876178f8248c6b1ed39afea46fb96a7566e77ca75e544434ebe8814a187d9308cf54c619da1a6bfe8f42ec52ed5dca7387b579de33373003341a038c0387dd0e42bfea8a94d25d6925861f8f5eae640802abca2ab6d2514d4708bc3db567f0711b6a5281436f81ebd5537413353eec55b4a9e32dc86b82ddc2d7defc9dc09b790cfe268bb56baea501cc14587cea30df
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155444);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-40117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy43187");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-4ygzLKU9");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense Software SSL/TLS DoS (cisco-sa-asaftd-dos-4ygzLKU9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service (DoS) vulnerability in
the SSL/TLS message handler due to improper packet processing. An unauthenticated, remote attacker can exploit this, by
sending crafted packets, in order to cause the device to reload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-4ygzLKU9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29eccd9b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy43187");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy43187");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40117");

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
  {'min_ver': '0.0', 'fix_ver': '6.2.3.17'},
  {'min_ver': '6.3.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy43187'
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
  workaround_params = [WORKAROUND_CONFIG['ssl_vpn'], WORKAROUND_CONFIG['anyconnect_client_services']];
  reporting.cmds = make_list('show running-config');
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
