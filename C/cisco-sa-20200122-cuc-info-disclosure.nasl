#TRUSTED a1826907f51fb39103215aad7daf5ff6d657e35a34de33ad10b038ed23a708441c2b8c04aa81255f985d0c62111640c48843b437777f44cb1e17a39c53c95dedcf921724482353fd1bd52bf12fac4bc22d7fe702556734faa4801421e18f754380525b18326af38e2cdd52ac67510560899bacca2420396d954e61b4f406c25d9267a585b225f94aedfe2a3b97dcbeaf9550733e97891ae80c6d6c4b2dd3f18e304369bcc788c76aef1dddf2dd83da1db359aeb2c86504976a430d486966d3ebef1fbf2ec9e96dc007c279fedd495bac4bc9f85b814d4442217200c4e103d9001dae32beb307c3bc755566a51942919bd7ac4962cd86fee9fdd2ef5ac01caf7b7afe083277829b6e2b8d40a9c8e4ac7e15410ab389666a74395502f90975eca29788ebe583612a06392a8d33c54c7caab31640b7acc84e76f831447cb916a3b12aad75b978e0dd7d3451a7a585fdd2732ced5556fabb30e614a1f12be2fc26ae101a83fa97c0fe48f9badb56eb5da1ec4b62f217b98196a5528f29600efb92ff9788376e7b2d37f6cb8789039529e2d1fdf887038409c46e7927f2755c0982ecb5bd433b1f2721ec88aac0d085acab84bde38d8c39a2c7e48b8bc932ce0ed833d36baed77d228babe32f71b155a90565268718a26457329ff02660a1a427162a0a0d2dcb5d683fae162d410301fb99b8ce691fca50856a8d3a5ddf0c25984115
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133403);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-15963");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr00922");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-cuc-info-disclosure");
  script_xref(name:"IAVA", value:"2020-A-0044-S");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Request Forgery Vulnerability (cisco-sa-20200122-cuc-info-disclosure)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager could allow an authenticated, 
remote attacker to view sensitive information in the web-based management interface of the affected software.

The vulnerability is due to insufficient protection of user-supplied input by the web-based management 
interface of the affected service. An attacker could exploit this vulnerability by accessing the interface 
and viewing restricted portions of the software configuration. A successful exploit could allow the attacker 
to gain access to sensitive information or conduct further attacks.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-cuc-info-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91a1b9b9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr00922");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr00922");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '0',  'fix_ver' : '10.5.2.21901.0'},
  {'min_ver' : '11.5',  'fix_ver' : '11.5.1.17900.52'},
  {'min_ver' : '11.5.2',  'fix_ver' :'12.0.1.23900.10'},
  {'min_ver' : '12.1',  'fix_ver' : '12.1.1.12000.55'},
  {'min_ver' : '12.5',  'fix_ver' : '12.5.1.11900.147'}

];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvr00922',
  'disable_caveat', TRUE
);

cisco::check_and_report(
product_info:product_info, 
reporting:reporting, 
vuln_ranges:vuln_ranges
);