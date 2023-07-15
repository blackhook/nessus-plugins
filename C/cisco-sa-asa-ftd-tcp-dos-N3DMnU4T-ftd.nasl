#TRUSTED af351b94f9fe8e8169657867696c207a4eb87a9a552e08774e2c5c0b24bc8f47b75e4beabcbd414115186ebf37578989b3694782f453d8d7c7da6ead63472366374993738f93132b1181077be9157ce7cc7ec78d76bfae87693206d2960eee92eb9186890465548c67d79f4a3349ea8fb7b74dead52ca0525b3094fd51d141aa72c9203351a348a78b4e0f44abfdbedc9cc34459864641a82b6506327d1f21e109640a25edfdc5b4b98c8dd0761140a0536fe7c88c3aa05b70ab8cdd14e7a3b5777259dc2fccba3b6458d3dec3e53857223d5873e0851127a02f498e05ee445ecfb5842d9144e5b1c7a249557c3e0a81b71d4124e43760f4c29d86ee83a7b3eba1eb45f4d6d170fe15e19df5fc855de4bc4c1a6fba30f31671d528b3c5895bf9e168111794560458aff9436eda96104a7125bf2cbccf01dd965403481d3c478d593c1decb780cb29f58b3be4e9d6d59784bb5e670e6995d6eddcd8938a3160385f6a51f383701a864e52d2a32d2d8f49e6822208f0ca9c2eb98631b5d42049eec3cfbf5eb2267876b64ca2d82bb1468e756a4f0dc0d9b97316c9993bdd94a6005cfb5f49f20adf4082a1dd91c3b9daa24a6bc3a88c8ee60d7746f18667128ef56b48ab8837d1f32d1d8103db64999216f12b91040fd261a145a22e9f5d4114cde373d158280eda81f695b4a5283efc3aeadc3cca21aadd07360367d736069bff
#TRUST-RSA-SHA256 acf40382bf55ac80993a52b27e45102554f082deb2e3e9d35cdc01bc7ecd4c4cd46bc521059a89b546756a72c6fffb5c6addfba12a4a6497759279609a86c9c1b654902be7798b62108af60c85a702035ea30936254239ff42de43ce955c0f85dbfff09c4d9ac978c9cd30c93d67622e366776cdc9b2bbd3da6637f996754dd621d9745a02e79e2a1597186e40fb5004942477993f44ff3445fec8dc1506b7b35833d9cd2d72adfb4a159d0145b3cc25930d53e0f503bacc5f34235c3a3949029f3861da35bee59383f0dbc5fd002d797416b7ad38d574e2a33e3addc61f9275e72d11633267635335b95de6cf16dcd20ac8a6cf9b3514f01da1059ea0fd7ea711c05738b7960d30dce3d889bad4a6cbd65c21729cff4223b65c11f105757fa55f67d8d9da8f2dd8830564321bb9f40093112562809c5c0628de0dbe175ed74d18c7a60e5f5dfbb3741dac392825775442c5f01f434fc4e58f3a7f8777affde08c3717fb27e340628ebf9e4f0ed6bff4870fdefc010fdc35b8a6ce0406b16e4f0838a15fb9ebc89de6baa5581bb90332919937925e3185267abedae89c345b0dc88ffb52a8197229d108f6eff61a4c409a5c965adc10dd528c4d1c0f3f74778590f92d6f5b5ac76527d00e761f6e66c703c0495cb9246a32d70fa730e58f1fa3af3d09fe3bd4d486a600cf512cd7035c8f09b80798d5a6e9858d69f2aca9614a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149313);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3572");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu46685");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-tcp-dos-N3DMnU4T");

  script_name(english:"Cisco Firepower Threat Defense Software SSL/TLS Session DoS (cisco-sa-asa-ftd-tcp-dos-N3DMnU4T)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the SSL/TLS session handler of Cisco Firepower Threat Defense (FTD) Software 
is affected by denial of service vulnerability due to a memory leak when closing SSL/TLS connections in a specific 
state. An unauthenticated, remote attacker can exploit this by establishing several SSL/TLS sessions and ensuring they 
are closed under certain conditions. A successful exploit could allow the attacker to exhaust memory resources in the 
affected device, which would prevent it from processing new SSL/TLS connections, resulting in a DoS. Manual intervention 
is required to recover an affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-tcp-dos-N3DMnU4T
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?574e4ada");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu46685");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu46685");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3572");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver' : '0.0.0', 'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.0.10'},
  {'min_ver' : '6.5.0', 'fix_ver' : '6.5.0.5'},
  {'min_ver' : '6.6.0', 'fix_ver' : '6.6.1'}
];

is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  var workarounds = make_list();
  var extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  var workaround_params = WORKAROUND_CONFIG['show_asp_table_ssl_dtls'];
  var cmds = make_list('show asp table socket');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu46685',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);