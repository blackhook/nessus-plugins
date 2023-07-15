#TRUSTED 2b1f818c431dbc62fc3ce18a5a42620337935e6407f037adf53a3f7029388b61c05462fc15b4c688463b71fb9283b85e214e75d6400f49d58b00a7691dce6e48f3f8d21e66b8e2b7d99f3be7053f67031cbc44fbd5ee7b4e2bf0ad4824fb69a089a846028dcc75ad16fd53702f6b6553a30ea811d58b310ea43127d09185f56310f133e7ab530d2e32af45b2eaa537089e61ab4db28bb3a83d8d6f1687313483002c7c29194b541ecd0b45039784d4026556b16e51c312a547d3b13b03437417ac451f38aa0367164c73c98bf58e089b7d10f8b2aca03625595f69603ca93187496dde7ae170f605a078da2e02306a5643ea99b9075115db5eef6794f0a46a5b30c3787f3102776826b8cabd2b59f9cf380213a0661088d552cfed90f437759e84a92f16b5a055b812af67ce7f8ea79b32eb769e86b88ccbb4247b407498777ac44a0948e70ef4881ac9becf54ef2fb10e736d159b48ded3e0b5397a5ee66f7b6e002cc44af43cfe0cca64a7f9a7c3b3717a5329a0dc1af6c119fda99e000da90aaa3a6e7b30cc4ec782a9b44abe13e9c92f474d4617613e72bb1bbaafc28b1718011fa242d3a0f31cb14cd9ff6628b2d8686f03a59a9e8c20b7be56ab9b10590fe48a0be2838ab06bfde5db43b42aa1919bc21d54041f1f528ae33eb795be3cc086aa710098974e98684203b592e8a3c85b3dae702f218cbad9b47b2b51fcee
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149354);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2020-3555");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu15801");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-sipdos-3DGvdjvg");

  script_name(english:"Cisco Adaptive Security Appliance Software SIP DoS (cisco-sa-asaftd-sipdos-3DGvdjvg)");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.6.4.43'},
  {'min_ver': '9.7', 'fix_ver': '9.8.4.26'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.43'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.2'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.13'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.19'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['sip_inspection'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu15801',
  'cmds'     , make_list('show service-policy')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
