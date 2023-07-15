#TRUSTED 8e21c240142f037cbdf16dba4ba8164ad4d002abe7ef763a367f639302ce9df66398d0855ad56e26293b4d4bd0f70c79a6ede6a0ffe1eea49b14a37c8aa9fdc22c92f1651972e4d7c0ae0526a68f305c955b6daae823e6eb124bce82d63a6ccc7e2a18891b8b1acea3312c3f9f7bbc7b09db3198672588a6719282e9158a0e715a9097c62b7a00fefd89628b8e433b34f581312385656577a2ddc3cbaf8f76901356789272584994eb9bea69c604444b8e617f5da8cb5724540c8d6b6c146318d6546c5200f3278adc20f8aa62dbacab533c52f49f159f14338e68a506dfee8660b97ecfe53f43ae42d4d70c31ef686b052bc36c0549fe97d237246f50fc090c3951504437ca3a1fee8c60c66713888103d7800ed6e4cb8bb3ee38588c9b44604e3ac17eb2e3f323980eb0fc53202e376171334a07af7095962217bd58aa0b4d61461cdcca3e2e49750775b5c1d4df0901169053fd3a9cbdf6d1dfa6dbb74a4df1c3f78333483f067358bcfab00dc40bbed855faf1cf4564435cef21157926a774dad1a51cc43a1edd10d900ada3ba9e44ac585d5cc4e4f0740f0a4cfecc46f0860dc44654ef2d47cd9c39e5e3baf4368b9d0884b75913dad4a49d8c2ccfca1d87ea1870955ca9de9d12e30a73b130d9b40ab5e5910ed45f895a9a39996954063fc6134ce99e78b775d2b9992b51be32f1cf1f01ddbc91ef10031e5029170b26
#TRUST-RSA-SHA256 063bdca999cf1a0e0a177565ff28d0d0272a3929ed850dc5c0f3391056ff875220729b82479bc439edefa329ffd9ad8c574ff788ef6c59484f2abe6db97d6d14330e96112857ddd5a890310811ddcceb859fc2765a3b6332b95ef17fd084163eb8b066fed4efb0390b97df3bd11c2735a3cb22994d310d62bf85ecafef30bee1e25c9f039320272233a74e148f45fc728e40695b450dfc7327da953b549ee617f75f2c393df2a9e0be2be29030ad9f906a9455ed0f9d156655c1f4a3e8f542dc37bb7f4190329d2fe1fc5bfa94e2bdecd4ffe07e6d535ab015f37003402073c6978a2dfa8502049ba0dae565dc83c93dffcfd05624c2daccd09485d6e030999015e291f91a35641a3edcad9352841cdf37871b35b7fe8264ad11a881515e441a622c5f888c6b3683148246e49bead87bfaf8fdbf4e1303dd697affbd4ab57533964dbc7238fa95eae0540d36d9f8bcab127df6ce2e8b5a2dbb37a9da9429481c3ec8ec361d6819a3d4697d3ab3cfb4a9a9c98bd553f51622ca6a3c30998e9df936064e6a0b3bb0c7095706a816f9dcbe0e6fde9075a9e88fdb3d7b88cc0a2acefc6f4a2cc38fdf635d2176d7cb8097452b7bd9de7f7546009d3d3b0289c530076b46bda09c34a7fbbd3c897c6b1cb76ab6e8fc7204e7a2930bf2ced727d42c31dda026aa59bdb1522600dd9218f5c565ac1b5dc8d0c4c93df128a0826a350702
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Inc.
##

include('compat.inc');

if (description)
{
  script_id(168367);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-1590");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz49095");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw45963");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx74585");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-login-blockfor-RwjGVEcu");

  script_name(english:"Cisco NX-OS Software system login block-for DoS (cisco-sa-nxos-login-blockfor-RwjGVEcu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the implementation of the system login block-for command for Cisco NX-OS Software could allow an 
unauthenticated, remote attacker to cause a login process to unexpectedly restart, causing a denial of service (DoS) 
condition on an affected device. The vulnerability is due to a logic error in the implementation of the system login 
block-for command when an attack is detected and acted upon. An attacker could exploit this vulnerability by performing 
a brute-force login attack on an affected device. A successful exploit could allow the attacker to cause a login process
to reload, which could result in a delay during authentication to the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-login-blockfor-RwjGVEcu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bfc8d32");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74640");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz49095");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw45963");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx74585");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCuz49095, CSCvw45963, CSCvx74585");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var vuln_ranges = NULL;
var version_list = NULL;
var cbi = NULL;
var is_aci = !empty_or_null(get_kb_item('Host/aci/system/chassis/summary'));

# Cisco MDS 9000 / NEXUS 3000, 5500, 5600, 6000, 7000, 9000(not ACI) / UCS 6200, 6300
if ('MDS' >< product_info.device && product_info.model =~ "^9[0-9]{3}")
{
  cbi = 'CSCuz49095';
  version_list = make_list(
    '6.2(15)',
    '6.2(17)',
    '6.2(19)',
    '6.2(21)',
    '6.2(23)',
    '6.2(17a)',
    '7.3(0)D1(1)',
    '7.3(0)DY(1)',
    '7.3(1)D1(1)',
    '7.3(1)DY(1)',
    '8.1(1)',
    '8.1(1a)',
    '8.2(1)',
    '8.2(2)'
  );
} 
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCuz49095';
    version_list = make_list(
      '7.0(3)I2(2a)',
      '7.0(3)I2(2b)',
      '7.0(3)I2(2c)',
      '7.0(3)I2(2d)',
      '7.0(3)I2(2e)',
      '7.0(3)I2(3)',
      '7.0(3)I2(4)',
      '7.0(3)I2(5)',
      '7.0(3)I2(1)',
      '7.0(3)I2(1a)',
      '7.0(3)I2(2)',
      '7.0(3)I2(2r)',
      '7.0(3)I2(2s)',
      '7.0(3)I2(2v)',
      '7.0(3)I2(2w)',
      '7.0(3)I2(2x)',
      '7.0(3)I2(2y)',
      '7.0(3)I3(1)'
    );
  }
  else if (product_info.model =~ "^5[56][0-9]{2}")
  {
    cbi = 'CSCvw45963';
    version_list = make_list(
      '7.3(0)N1(1)',
      '7.3(0)N1(1b)',
      '7.3(0)N1(1a)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)',
      '7.3(7)N1(1)',
      '7.3(7)N1(1a)',
      '7.3(7)N1(1b)',
      '7.3(8)N1(1)',
      '7.3(8)N1(1a)',
      '7.3(8)N1(1b)'
    );
  }
  else if (product_info.model =~ "^6[0-9]{3}")
  {
    cbi = 'CSCvw45963';
    version_list = make_list(
      '7.3(0)N1(1)',
      '7.3(0)N1(1b)',
      '7.3(0)N1(1a)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)',
      '7.3(7)N1(1)',
      '7.3(7)N1(1a)',
      '7.3(7)N1(1b)',
      '7.3(8)N1(1)',
      '7.3(8)N1(1a)',
      '7.3(8)N1(1b)'
    );
  }
  else if (product_info.model =~ "^7[0-9]{3}")
  {
    cbi = 'CSCuz49095';
    version_list = make_list(
      '6.2(18)',
      '6.2(16)',
      '6.2(14b)',
      '6.2(14)',
      '6.2(14a)',
      '6.2(20)',
      '6.2(20a)',
      '6.2(22)',
      '6.2(24)',
      '6.2(24a)',
      '6.2(26)',
      '7.2(0)D1(1)',
      '7.2(1)D1(1)',
      '7.2(2)D1(2)',
      '7.2(2)D1(1)',
      '7.2(2)D1(3)',
      '7.2(2)D1(4)',
      '7.3(0)D1(1)',
      '7.3(0)DX(1)',
      '7.3(1)D1(1)',
      '7.3(2)D1(1)',
      '7.3(2)D1(2)',
      '7.3(2)D1(3)',
      '7.3(2)D1(3a)',
      '8.0(1)',
      '8.1(1)',
      '8.1(2)',
      '8.1(2a)',
      '8.2(1)',
      '8.2(2)'
    );
  }
  else if (product_info.model =~ "^9[0-9]{3}" && !is_aci)
  {
    cbi = 'CSCuz49095';
    version_list = make_list(
      '7.0(3)I2(2a)',
      '7.0(3)I2(2b)',
      '7.0(3)I2(2c)',
      '7.0(3)I2(2d)',
      '7.0(3)I2(2e)',
      '7.0(3)I2(3)',
      '7.0(3)I2(4)',
      '7.0(3)I2(5)',
      '7.0(3)I2(1)',
      '7.0(3)I2(1a)',
      '7.0(3)I2(2)',
      '7.0(3)I2(2r)',
      '7.0(3)I2(2s)',
      '7.0(3)I2(2v)',
      '7.0(3)I2(2w)',
      '7.0(3)I2(2x)',
      '7.0(3)I2(2y)',
      '7.0(3)I3(1)',
      '7.0(3)IM3(1)',
      '7.0(3)IM3(2)',
      '7.0(3)IM3(2a)',
      '7.0(3)IM3(2b)',
      '7.0(3)IM3(3)'
    );
  }
}
else if ('UCS' >< product_info.device && product_info.model =~ "^6[23][0-9]{2}")
{
  cbi = 'CSCvx74585';
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.0(4m)'},
    {'min_ver': '4.1', 'fix_ver': '4.1(3d)'}
  ];
} 
if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'affected');

# check if login block-for is configured
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']); 
var workaround_params = WORKAROUND_CONFIG['login_block-for'];

var reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config'),
  'severity' , SECURITY_WARNING
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);