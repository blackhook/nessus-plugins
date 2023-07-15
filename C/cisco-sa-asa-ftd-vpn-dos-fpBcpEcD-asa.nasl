#TRUSTED 9cdeaaeb101a0e23e82ceaa0829ef374554553aadc101d360bdff1939426372e5a532c58d3947e675c6885f572526c373f135a62217fd0090ca49539a142487bbb40360f70c82f4ef92915d65587aca59f467a0cefe1309a6c952798de46ed3dfb0cd5547a44a0f963e178adf9ca971747a7085bfe5d8c75ca3dd2934e8e8cea927cf2055e430c0adf307d21824ec9e211cb4af85a9856a9fbc79de98f13dd9e8d7a87fc8e26d024dd8a7c42779562ba82aa9dc9d7d79e7a11acb3139c550ac73dd6943a7002168933296e6a9359fd7c8460a2382ae00886218c67452d2f0ad98751d152cb9bdbf14833dbdfabd7e14fd1a77087761956a85f2e942e679fa717dc81025717d5724caf54d2fb7ccc7727c223b0e55adf231a3190a9345ce8306d4df63466cd1d3dd4dc7ba3b2ec78d85455643b2a04571e8bd3c309538fa1a864ca6bc0f16cf9fd9b3e807df102b87aece790cb7f5fbcf2ec2bc9832f46a4a97fc4d83d6ce6816d7a3657c8d96baac5080e1ed98de6ace2d60b40c1e80f1d6fa12355174562dceb706fc7ae5e1e19984031895b875f681202cf827f93a208d28d58f669406b0b92aa4c53e7b13a14b60ec48767d964766951674475a4ca5a5ab6ac771bb4ccd51a3ca3a405a05dde991a8272299ce5babf305fa4273ceaae462e2d1292175e9100bd5d9b83222f692592d7e87deb69c2a118f82d0f307ce562ee
#TRUST-RSA-SHA256 1521b6719302aad62eeafde52a1ee06750b25b4be466ceb299a2d0807438c1c4e9daa1b7bfbe9879efd52bdbe02e66ca43aabe52cc544ae8b76187e12c061b370ac5d16f70f8e1ae7dea37d92b085f6083836b03f4ccc5e9fed4d9439d06967f94b5ef2ad9b8f3a063b95e0f8a8832ecf04aebbccf00ce257269d7e67fa9c542c03a9d6c4d4e9ed1a8fb726b71eb0d0464f36feeb48593b62b3e1e798263429a05347889e4e9aa36a1420943216b193d99dc893de2289e26b3387b9a169521e1935d4db2a9dda7e3c262e9b46c8b95a8fba6d6ce7b60da552c5cb2d302a25ab804c614b068d4994c2eb2e606dba117e35d6eb7b0a3ae366eed9bb75a1c183fe2de78b4066de0d544776de202f1901134fd17a0db15f40ba4691d8540e849add791262b6b3f7bbce11847866a68e9e3b65a09064c316e0978b261a8775e44babd22117807cf45495b9045166f1c7863ca9c7aa667d21e0ac2bbf12e4856a40810c5c917e6c14d251b2376adc3fd8608c9cedda3ed224e6b85d5879be404adaaef13fa806bc6684cfa9c1050c79ca9fec1ed247347d9e29df3c84c9d7cec803921cc7d96c834c96b43f066163281b0eba4fd9d09882405e8c1848e28befe5cd9c23b21fc547579b2e53e75c767e938e5746b88b0133a1b64bba8157eeda811fd3898bc729f3cb17af5e1908f88314045322beca6ac43e4993b43d447b5b010c587
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149304);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1445", "CVE-2021-1504");
  script_xref(name:"IAVA", value:"2021-A-0205-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv56644");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv65184");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-vpn-dos-fpBcpEcD");

  script_name(english:"Cisco Adaptive Security Appliance Software Multiple DoS (cisco-sa-asa-ftd-vpn-dos-fpBcpEcD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by multiple denial of service (DoS) 
vulnerabilities. A vulnerability exists due to a lack of proper input validation. An unauthenticated, remote attacker 
can exploit this issue, via carefully crafted HTTPS request to an affected device, to cause the affected device to 
reload.  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-vpn-dos-fpBcpEcD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e9b06b9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv56644");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv65184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv56644, CSCvv65184");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info, vuln_ranges, workarounds, reporting;

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver': '9.7', 'fix_ver': '9.8.4.35'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.85'},
  {'min_ver': '9.10', 'fix_ver': '9.12.4.13'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.21'},
  {'min_ver': '9.14', 'fix_ver': '9.14.2.8'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv56644, CSCvv65184',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
  