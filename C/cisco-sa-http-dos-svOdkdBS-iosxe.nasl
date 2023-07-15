#TRUSTED 243af78d8b3647f4185697d7505dc44c56c42afff004ea0b386672e512c284200a1e6a9192d59882eef2ab53f496f6f9b8e468867abc3f0127da5b4b45bb6f3bc385a57f411a7da31a610e17a21a745677c17c55348973a26e2869dd5a8c287f1ae8142d6991b272ae04b3d6ee142b9b7da2ab370d3420fceeb4bbf1c78b7716357decba59b810a1a808638d9f23daf5e308361f7961f503a0665138c530869788e59cfc83b652b2f839b034e322e373a9e958830a3dac7453a21a30ce43a2f2b4e59d392ec202b7e81979aac8899397c87ac624d2b71e761cbcc5ecdb45c20da5cb3874dfbe3ba1871a9e36e02504f9d3ac6ab01e1189ef95a6161f35d538aa10ae128e09cf901fca449ee634b20ea65e99854910df4b6c273aad16daaa2116fde0e6ecb7b43a07faa7f38075de27bdcd2aa8015d26600bb06b86d59befc2c38b457d20e834103b96c074fdef24ad102561d587ad247446e402c8e078df77aab4b0b6e94890134a2b6993538627d7973b510fd05405982b923deca28c16ffb09a2f740622ea4a0e885df9e6ff9c97ff853cf06158da6954624722356252c962b4591c1b17740afebd1dbdbecdef31d6548663ca037a854b929f4c7dca17a258c723fa29ccd5b44791d9a485ba2cee8c6bc233f19cd4d39a8f6f348ed3b2fb510c69ca34792a7766336fd8f11549072eb4cbab16b0017be8d4643d5fc96ce8aa
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161364);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2022-20697");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx42406");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http-dos-svOdkdBS");
  script_xref(name:"IAVA", value:"2022-A-0159");

  script_name(english:"Cisco IOS XE Software Web Services DoS (cisco-sa-http-dos-svOdkdBS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a denial of service vulnerability due to
improper resource management in the HTTP server code. An authenticated, remote attacker can exploit this by sending a
large number of HTTP requests to an affected device to cause the device to reload, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-dos-svOdkdBS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a1d2a6d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx42406");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx42406");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(691);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.11.3E',
  '3.11.3aE',
  '3.11.4E'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['generic_workaround']
);

var workaround_params = [
  WORKAROUND_CONFIG['HTTP_Server_iosxe'],
  WORKAROUND_CONFIG['active-session-modules'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvx42406',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
