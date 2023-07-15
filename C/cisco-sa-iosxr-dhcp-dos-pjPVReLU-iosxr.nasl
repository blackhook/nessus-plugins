#TRUSTED 12b4efd9c33e97409099507c80489c0739a7930544da274f72f42e6390389ad8f41fb2d8dab2fd3df7c396822dedc1989400c7a927dcba4ed6afdc18c0e83c3a74cceae641df5cff0f46d06f1ffc7ecc19e3a7698adea2a599f06267b9a385dd732d4c3fb729afd871309d07a40a8d60329afd86c8f9b4d29bb8cc2f301240887084ea354a9043c7c572ca8126c9b0b1a98e27541af3a256eb642a54dbdeb2b01a471212b790aa94eac22e2ed5769977be68936e502a9172a7380975e24c0f0d122018546a7033f4486ee448a3ddc79ef43fc639d3c23a493095ed43591cc427c7b046da75cde8262495ac9efabac4ef3c780a5924afa661b3901f564b5dc9fdbeb65427be18fcfad3f03b4e3ef0b0b5d8fe16179446bb26b4b6d0a58cddb38c5ce35a6ac0490e0eb3711cb493ab834ac45b64cd8058b9f251f18bb96b937e68b33f3acd6bcd1a6375eef918712c4b2ccdbe44ca50b1d07a876247f25cba753f9ca843b00f4003723bd3f5abe5429ab4910bd43a3d3bd3de3d38177186cb8e11c1826f2b283f294d762d57bec8b9258b5498f8a3f98ab8834296b82b1ceca7040df9e99367832dac7d1a9d1b7faf127b81dec2d2541f51a1c907039eaa28521e3d735feda63d6a0dfa086840a47b9617308ef6c048e6c3f0b2e79e588913f7377def8c39fd542c62b4eaf64ca764c81e318c1ca3e8699b19a9ce7674b4a90d15
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153207);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_cve_id("CVE-2021-34737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw95930");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-dhcp-dos-pjPVReLU");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software DHCP Version 4 Server DoS (cisco-sa-iosxr-dhcp-dos-pjPVReLU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability in the DHCP version 4 (DHCPv4)
server feature that allows an unauthenticated, remote attacker to trigger a crash of the dhcpd process, resulting in a denial of service (DoS) condition. This vulnerability exists because certain DHCPv4 messages are improperly validated when they are processed by an affected device. An attacker could exploit this vulnerability by sending a malformed DHCPv4 message to an affected device. A successful exploit could allow the attacker to cause a NULL pointer dereference, resulting in a crash of the dhcpd process. While the dhcpd process is restarting, which may take up to approximately two minutes, DHCPv4 server services are unavailable on the affected device. This could temporarily prevent network access to clients that join the network during that time period. Note: Only the dhcpd process crashes and eventually restarts automatically. The router does not reload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dhcp-dos-pjPVReLU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce07f05c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw95930");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw95930");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info['model']);
if (empty_or_null(model))
  model = toupper(get_kb_item('CISCO/model'));

# Vulnerable model list
if (
    ('ASR' >!< model || model !~ "9([0-9]+|K)") &&
    'XRV' >!< model &&
    ('NCS' >!< model || model !~ "(55|56|50)")
   )
    audit(AUDIT_HOST_NOT, 'affected');

var smus;
if ('ASR' >< model && model =~ "9([0-9]+|K)")
{
    smus['7.1.3'] = 'CSCvw95930';
}

var vuln_ranges = [
 {'min_ver': '0.0', 'fix_ver': '7.3.2'},
 {'min_ver': '7.4', 'fix_ver': '7.4.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['dhcpv4_server_proxy'];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw95930',
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config dhcp ipv4')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
