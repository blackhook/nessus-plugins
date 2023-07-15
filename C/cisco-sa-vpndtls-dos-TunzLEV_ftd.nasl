#TRUSTED 8c3e8db0fd45f2a6c96f027c12b821a09fe7ec599fc0f62ac92ade109e7e128e7711bc3be7e54955060e8fc17e3104daa993d3816a6be3a2be9d1560028fcca9afc3f5f57dff095173199277d59d5024d5f85f0b2832d8471732f108d8ac32ce807fc37f796912155f7193b43a38d15f6cf268581dc2a5a9c04cecc615cb56006927561bfdcfebb413cb769b2e548f078b751c314e8356246e68e1210e2fab3268a80338207e5a4769081031fbe7887913fac8a92f7daab3fcf90c45bdc455dc5b5b3859aa4a6b5138b2d83f99977931b76a4b70833902b4c9cc63d74e6147ba40a4f801f2b8041e4f5dc7c393e3d64566831452eb942079c316ce964efea8c73c3c331bfa9cb9718ccdbef404c4d8fb663dd9e2eddef630543f315ac40901233b7aa06e870bda01c2c182e6a6732fd34397d5296897480bd86888527ffabfafcfc1cf986e84ad3e74c7184c2bad5f5d400f645b1210608ef309e436f8dd9ec2f44b1f640f4faedb713dd847311d450a1ec4e36661112e871a750e89a09f157dd4edfb35965d08bd960839aa6213a8c67dd8b7e68d9af7e236dd78c42ff39dddf62a5f1fd219671d3afa2d1e2dfe819d9fde787346456d14b6daa5aee051c0e87a4c4f7e620f8bc98219eeee6fa7e53b489be9c69924e6c6d17605f8896faf316ee58b07d30f72f31ebbf4462f678fea20945c3dcfa8667c9bbb2a783d277fa1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160306);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-20795");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz09106");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vpndtls-dos-TunzLEV");
  script_xref(name:"IAVA", value:"2022-A-0180");

  script_name(english:"Cisco Firepower Threat Defense AnyConnect SSL VPN DoS (cisco-sa-vpndtls-dos-TunzLEV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability in the implementation of the
Datagram TLS (DTLS) protocol that could allow an unauthenticated, remote attacker to cause high CPU utilization,
resulting in a denial of service (DoS) condition. This vulnerability is due to suboptimal processing that occurs when
establishing a DTLS tunnel as part of an AnyConnect SSL VPN connection. An attacker could exploit this vulnerability by
sending a steady stream of crafted DTLS traffic to an affected device. A successful exploit could allow the attacker to
exhaust resources on the affected VPN headend device. This could cause existing DTLS tunnels to stop passing traffic and
prevent new DTLS tunnels from establishing, resulting in a DoS condition. Note: When the attack traffic stops, the
device recovers gracefully.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vpndtls-dos-TunzLEV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?864a3e06");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz09106");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz09106");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.2.2', 'fix_ver': '7.0.2'},
  {'min_ver': '7.1', 'fix_ver': '7.1.0.2'}
];

var workarounds, extra, cmds, workaround_params;
var is_ftd_cli = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz09106',
  'fix'      , 'See vendor advisory'
);

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  reporting.extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['show_asp_table_dtls'];
  reporting.cmds = make_list('show asp table socket');
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
