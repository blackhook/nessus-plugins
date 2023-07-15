#TRUSTED 645e5e18f9191eb723c3f4d5e015b608a19f4f765c4a20c8de2f177926ae5a1ae8c500b2fbf3fe02cfaa5d03f85b792e60108895caaf7da68bed5ce71747cc8a129371bfbc3e0ff0ba4c69834618399a1faecc3e96cd8adb81f1db9e35135f87a108b34e8c901d91ccdc00a5c54dd3aac7b0acae4c198b9e2e15a0b4c35162ddb9056639281f0f06ac54239fcaf3477006312b3d4f71ce4c372375112e44b61b743b65b9744a37e16603e6c9961c2834127200e5a6c84b564394eff7b86cc394521070963717cd87c8a8c53d0fa43ba05dc8fbdcf9747ec4b7eec723e839a56ba6a63da6193e6b592f97c0f09fcaca6c2946d33544394666670845e16bd49d2dbeb8cbc24688d0e5dfba3993ed2028ff217bbe97dbd2897e261f0f0608df04f91fa5709622b480e343521966e58670be853112db7d3cfaef9d65b81fd7bfbb78f93fe77a5c61cb0c47c5939bd2f472513c49abf988f1e3894dc134a908d99872f8925de27af80cc4c6d30f1f044f8a73db0885fbbb9f4dde7727e0c504815d81ee01ed6a6998823cfde360dd272dc12105019e4fb92d6ed8190c8ceeac4b1f4b19593b4c7b66d1f3adc514c91d3839c57dd2e91052d773c494eb61d41e5fe04f7be98445eb508bd103251f6c70471996c9e26aceafe13c1cbd3fb8bfd6f9e68c9133ec6031a34f75cd26857b4e57cdfce46c9851f6c47bd43c6afd4cfd1dce68
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161363);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2022-20697");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx42406");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http-dos-svOdkdBS");
  script_xref(name:"IAVA", value:"2022-A-0159");

  script_name(english:"Cisco IOS Software Web Services DoS (cisco-sa-http-dos-svOdkdBS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service vulnerability due to improper
resource management in the HTTP server code. An authenticated, remote attacker can exploit this by sending a large
number of HTTP requests to an affected device to cause the device to reload, resulting in a DoS condition.

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var version_list=make_list(
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.1(3)SVT1',
  '15.1(3)SVT2',
  '15.1(3)SVT3',
  '15.1(3)SVU1',
  '15.1(3)SVU2',
  '15.1(3)SVU10',
  '15.1(3)SVV1',
  '15.2(7)E3',
  '15.2(7)E3a',
  '15.2(7)E3k',
  '15.2(7)E4',
  '15.2(8)E',
  '15.2(234k)E',
  '15.3(3)JK100',
  '15.3(3)JPJ8',
  '15.9(3)M2',
  '15.9(3)M2a',
  '15.9(3)M3',
  '15.9(3)M3a',
  '15.9(3)M3b',
  '15.9(3)M4'
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
