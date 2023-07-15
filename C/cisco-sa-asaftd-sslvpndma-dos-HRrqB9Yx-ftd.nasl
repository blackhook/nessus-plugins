#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168873);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3529");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu59817");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-sslvpndma-dos-HRrqB9Yx");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software SSL/TLS DoS (cisco-sa-asaftd-sslvpndma-dos-HRrqB9Yx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the SSL VPN negotiation process for Cisco Firepower Threat Defense (FTD) Software could allow an 
unauthenticated, remote attacker to cause a reload of an affected device, resulting in a denial of service (DoS)
condition. The vulnerability is due to inefficient direct memory access (DMA) memory management during the negotiation
phase of an SSL VPN connection. An attacker could exploit this vulnerability by sending a steady stream of crafted
Datagram TLS (DTLS) traffic to an affected device. A successful exploit could allow the attacker to exhaust DMA memory
on the device and cause a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-sslvpndma-dos-HRrqB9Yx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24a25658");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu59817");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu59817");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3529");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
var model = product_info['model'];

// Cisco Firepower 1000, 2100, 4100, 9000 Series
// Cisco ASA 5500-X Series Firewalls
// Cisco Firepower NGFW Virtual
// Cisco 3000 Series Industrial Security Appliances (ISA)
if (model !~ "(FPR-?|Firepower)\s*(1[0-9]{3}|1K|21[0-9]{2}|2K|41[0-9]{2}|4K|9[0-9]{3}|9K)"
  && model !~ "ASA55[0-9]{2}-X" && toupper(model) >!< 'NGFW' && model !~ "ISA3[0-9]{3}")
  audit(AUDIT_DEVICE_NOT_VULN, "The remote host");

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5.0', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ssl_vpn'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config'),
  'bug_id'   , 'CSCvu59817'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
