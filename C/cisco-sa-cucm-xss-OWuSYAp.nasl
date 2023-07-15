#TRUSTED 247ebc1bba80a3f7b62f6683ee9d543eca27f1ee663c657171ef16f491e526fe1af3500e18bb38588d5aa17e8ef18997a496583e84710b78dd55960699231ae0125c28ea49af07f802b972bec1173a6e287683ceade646f950faeb06918855b71cc4374d38e36a6c81c8f73082baa6400b0cd838e083b3a452ddaf800e52474fe03c5fb33a469da5ea8a4af4d7c8737b31a4539837d5234ffb7e39288e5d24ad4ada523ac8a7ffd9181c8ccbf5804ccddafccb7dfd955c7ae870eb61d7cbaeb6cf903ed54bf5e89c371e1838704e55bf475391419f04d3a8cc0931af961c1f1377211633bb7c5182a43d5383494f01262c7b28607bc0f8b52973a794b2111a2c63634f8ae439f31b5d81bf4618dbd0be3fbdf79d6c8eca9dab63c0c13a74f688b50a14b2699c996b489d43f6920df68a14658d71fd7838ab3bc06cc2532288e3df07543c1079e0a26113ce498e0679fa9fbeeab4b2301343fa006829e27596dcd342bc0ccc06408eebcc3204a6e765006b38322e95530f5aaeef255d3ff7f2449fcb0478ada7e62dec5e8328089c6d55ca35890329c0662ceafe2ee0b80b700d1b993ed6b13280ed2c7d7e48e4ad793c5588398ab4a1cef89d6162e1cd756700d75bdb84df309b0860433b850e8bcbe99aa1b10389e80fac6292a060cd7419933652c5048d7cd80e77feb3362800a0e664b0065201f41ee30c6f07dc30682adb
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139229);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-3282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs29695");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-cuc-imp-xss-OWuSYAp");
  script_xref(name:"IAVA", value:"2020-A-0297-S");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Scripting (cisco-sa-cucm-cuc-imp-xss-OWuSYAp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a Cross-Site Scripting
vulnerabilities. An remote attacker could exploit this vulnerability by inserting malicious data into a specific data
field in the web interface. A successful exploit could allow the attacker to execute arbitrary script code in the
context of the affected interface or access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-cuc-imp-xss-OWuSYAp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef22b106");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs29695");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs29695");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '10.5.2', 'fix_ver' : '10.5.2.33225.1'},
  {'min_ver' : '11.5.1', 'fix_ver' : '11.5.1.18900.97'},
  {'min_ver' : '12.0.1', 'fix_ver' : '12.0.1.16574.1'},
  {'min_ver' : '12.5.1', 'fix_ver' : '12.5.1.13000.17'}
];

reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvs29695',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);