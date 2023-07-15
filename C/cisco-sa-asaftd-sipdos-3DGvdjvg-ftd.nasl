#TRUSTED 5c26b3362ef99500956fa70de1bbfcfacb41984c6f94e9c7bfc3a03dc070191a036362dd95412cd34a50a66de4d7879061eacef96e8ce0497aa6c7aaf12cb9e1407e273cbe9b58c56c7a34d70b11f053cffcd497f5a0b07663869c2eb0492ce4449a9b26c4fb90094d487e8dac639dbd8722c8ac5359ffba2850538d3c08636f2dde17b931dd62218220ef3ce4de7fb2bef7f02eadb2010b6fc751d77ca1d9e867395119a818f9d2871aaad4f13c9b9da42f0d3a16aa4eb1a484f43be643a3f19c1784a94cfa98ad62f3662a24f868c6449dc4073863fd8effdd073d46ee1ba3c65f4cfcbe5a0f60b15fb6fdb1054752542e2d99258417681d80fab26088adcc1d72f5b23aa927a7b3d38ce29c5c91d291c71ddae0a1f5ae61497768d9b635b517e5ab3633e5d5bf9c0959730f78bd2ab2c69c62e8b9188d02571284201268e1b08a09172eaa7db87043d73e90d8f25872febf1d3128fa7f29533dfaa203d7fdd6dd70c9f28268ef88ac158909ce91e4e5e3fed8630964a03c1eaa51c76a68fa90710d9603252430f7a633e93ca714f37add8b43214e9fcdc8e0aedd1153638d6ae60e4741318615008403b200413153ea6e63c3c8551e364c0ec15c1648cd94f98068753a0177082118c9cc1d2031a419752971f14f324ccb609dd1239790beab84dd693debebc14227708cafd038591ff51c628805c059a60741c8876e4d5b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149355);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2020-3555");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu15801");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-sipdos-3DGvdjvg");

  script_name(english:"Cisco Firepower Threat Defense Software SIP DoS (cisco-sa-asaftd-sipdos-3DGvdjvg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the SIP inspection process of Cisco Firepower Threat Defense (FTD) Software is 
affected by denial of service vulnerability due to a watchdog timeout and crash during the cleanup of threads that are 
associated with a SIP connection that is being deleted from the connection list. An unauthenticated, remote attacker can 
exploit this by sending a high rate of crafted SIP traffic through an affected device. A successful exploit could allow 
the attacker to cause a watchdog timeout and crash, resulting in a crash and reload of the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-sipdos-3DGvdjvg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?421e590f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu15801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu15801");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3555");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(404);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5.0', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];

var is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
var workarounds, extra, cmds, workaround_params;

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['sip_inspection'];
  cmds = make_list('show service-policy');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu15801',
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