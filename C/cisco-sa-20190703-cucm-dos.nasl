#TRUSTED 8d5d386b85d0dfc42d911c55984072c89a2988889ecba8e96a0e19370bde88cb423c107b3fc2850d85a43e541c512f2ecd471e884d65b00ceee538c809378577dbb181b6f8be1fc1797daeaded21e3ceacb12486ae1f96bf98e942e9a0e6b45c61c03de3a1d6a197b4738ae0c1042cd4a64cd7639f5d0a9496a8a2f4d1bab1a75b20ca9ee9c649afab1fe2f7f28a8f4175b7265bc806b2de6ad3a127cb8d1f98370cd849b7d25a10e8c2f56b8e506616a470ecea9b906bfefaf2222af1d3a5fb4f60b90cb962977cec5dff87f22904a141a3ae8a65355aa5e2cbd0662c01ae0b855fdc31b3222e88b19cc0e9b32274124abee55ad8cc609b2811c83f1c0b17c061fb1274bb0c90581dacca27b212b80c4638fea20b12cb648ef672785490ea80b6ce849ffeca0612f52f1391de01a1fd4c4f723e50d8ad73f1b0f345decfad4c3dd3e90320e6956980263adfc07b112a7663b52605c7cf544e11b9fd5d3fcc0a61958fa6df9d39ef54920a8f1d58501b3fb4a1dbea1a246afae76ab159c3810f5c7f9bf11fdb2af394d0de55da2b16fb976519159e38da45a694650a38233fd842d2a7807443eeebfa1c385700ca39f2c612d1bb60804ffbb18cf22db715170d8432ae94c5ef4ebd8aecaaad99d1830926956871118a3105d6637199d16ce2e3669f90020f91916746576cee6a4a5c129ed0eb1a733093807a52905c0385b0d5
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126644);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1887");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo70834");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-cucm-dos");

  script_name(english:"Cisco Unified Communications Manager Session Initiation Protocol Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a vulnerability in the
Session Initiation Protocol (SIP) protocol implementation could allow an unauthenticated, remote attacker to cause a
denial of service (DoS) condition. The vulnerability is due to insufficient validation of input SIP traffic. An attacker
could exploit this vulnerability by sending a malformed SIP packet to an affected Cisco Unified Communications Manager.
A successful exploit could allow the attacker to trigger a new registration process on all connected phones, temporarily
disrupting service. Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-cucm-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbdacd35");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo70834");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo70834");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1887");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.17900.13'},
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.15900.18'},
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.22900.11'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.10000.22'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvo70834');

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
