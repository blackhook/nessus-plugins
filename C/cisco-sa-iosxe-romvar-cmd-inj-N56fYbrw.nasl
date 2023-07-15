#TRUSTED a7790eff2c489ea5a042f0e366874f9b98a6248f333ae6da3359fe6b4b7b6fc97d6c1e5996dafb100033cea9403b8bdfba014ccd2d93f22995e2b467b31b10eb070d7cca8be69c59dc18cae073d4316e28167aa43165cd3a3b395e0e11ff5efa9fed54be7c1e4ddf81819128a94b42a77dde66aeef8ea39b7d8acb21ead22e926ed94f924ce91953017a3af994a87d5e64b3449ead1adcd8fe04e31d26c09c8f50574eeae193069c62aa520e903e4a76c760b57e8846ac55ff2b5c7104d8c5c0945a0ba29cc20ea073085e6c6d8a5907a1220946f2cc6906fda21a373a0820b812679993d84dbe756400373a96b658585f3cf55fa533aa0e03f06fbc422b2c7159b86c1532c40150f406542f358051272e7bef868c2f713c663e938198c68faf0a66eb1de1afae955421948becc06602a498c424396c5402e14dca5b5ad1c4f5a996712518c9ac367381bf01ac426a415b51999d9613a7820a640892841c089d5ac20da7eefe87c72f39d465488ed2a0b3a7ed5925fbca842ed85e7a392025789a566b0a7830445e787ca911cab44ea1574853fe5507b5c4dc52de5bfc2fcdb1d6ba06686be263bbfaf762bb8c4a64674dd1c86b58d9843c08a5c8eeff275f27e7b4d279d36e4647345d1aef0496840ad8f660f3d3d1813750d0d3d0e0238826c034c8527d8082cc5d19c4b5fa77adb9bf84b2152da3992cd143593a2cc8c3d1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148427);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1452");
  script_xref(name:"IAVA", value:"2021-A-0141-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu65039");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-romvar-cmd-inj-N56fYbrw");

  script_name(english:"Cisco IOS XE Software ROM Monitor for Industrial Switches Command Injection (cisco-sa-iosxe-romvar-cmd-inj-N56fYbrw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a command injection vulnerability due to incorrect 
validations of specific function arguments passed to a boot script when specific ROMMON variables are set. An 
unauthenticated, physical attacker can exploit this by setting malicious values for a specific ROMMON variable, which 
can execute unsigned code and bypass the image verification check during the secure boot process of an affected 
device. To exploit this vulnerability, the attacker would need to have unauthenticated, physical access to the device 
or obtain privileged access to the root shell on the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-romvar-cmd-inj-N56fYbrw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d36bd6dc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu65039");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu65039");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1452");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Vulnerable model list, note regex is case insensitive
if (product_info['model'] !~ "IE[\s-]?3[2-4][0-9][0-9]-|IE[\s-]?34[0-9][0-9]H-|ESS[\s-]?33[0-9][0-9]-")
    audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info['model'] + ' model');

var vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '17.3.1' }];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_rom-monitor_rp_active'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu65039',
  'cmds'     , make_list('show rom-monitor rp active'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds  : workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);