#TRUSTED 34a4f89ff2ed0e1bcd5626397d6db72d6b0264b1f8db1e93f7af423107f6ea003974dbca35fa98066520a79f51a3949b2ca7f7b2480f8035643527603a78dcfed6fe12e46eda32b8a2481a99a61c6ac1fc30819572d650755048af46e4005866cb26d8e81dc4c8a113b65b456a25d3ad2151ddbf4e212c485c4f17acb8e1e7fb100ac359a6d72786526a096d0292e70ce7904c0bff43c7d2252ec4693601329e54f321d3039af6bd24fbf31fe4b477ab829738ce80ef141522f1188335ef622400d05736260cb74a0a2c24883942e899a4958e51b29e695980a502b329fd79396702adaed64013bf6977a9a6e64bfbb769556d63949aa07597d2f0502fd14f4adb288894faa7ab4c618a87c55aabe8c876ddee2d2c1382c69d4bbffbb3cb640d0f34f4a92e62befda3be964bbd26a1b7b7032e3bdef1bf6e4b194443e87ce15a643292fc07cacf391a61261a5614f184125d1e5585ec85bdaa536945ea672352cec89911e2554dbd6fa508fcdbf4559c585adf62f0c51a420dc90f374f3655dbc8215de7a5cfda9ddab55e693955ee1ef20c6688074227e86c81ac3d27dea2cc0a20d8e135ab90f69170791f95dcd97056d3dd554188a3ec12dc1899a3217d982a0e8a1076f070ed2f013e712658ca4fe157edfd4d3be50060952a293a3c39d1582aa5122bacba47aeb5504ebb421672fbd31b35769be08d19963a36e5e754e9
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160763);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id("CVE-2021-40125");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy93480");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ikev2-dos-g4cmrr7C");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense Software IKEv2 Site-to-Site VPN Denial of Service (cisco-sa-asaftd-ikev2-dos-g4cmrr7C)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Internet Key Exchange Version 2 (IKEv2) implementation of Cisco Firepower Threat Defense (FTD)
 Software could allow an authenticated, remote attacker to trigger a denial of service (DoS) condition on an 
affected device. This vulnerability is due to improper control of a resource. An attacker with the ability to spoof
 a trusted IKEv2 site-to-site VPN peer and in possession of valid IKEv2 credentials for that peer could exploit this 
 vulnerability by sending malformed, authenticated IKEv2 messages to an affected device");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ikev2-dos-g4cmrr7C
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c784582");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy93480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy93480");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("Host/Cisco/Firepower", "installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy93480',
  'cmds'     , make_list('show running-config crypto')
);

if (!get_kb_item("Host/Cisco/Firepower/is_ftd_cli"))
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');

  reporting['extra'] = 'Note that Nessus was unable to check for workarounds';
}
else {
  var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  var workaround_params = WORKAROUND_CONFIG['ikev2_site_to_site_VPN_peer'];
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
