#TRUSTED 1139d812c5142ed384cb624af1a901ca27757be636b7d6dbea464f4c588aa3cddbfbf9bed8da195b8e652480abc2d18c62f7844f67b68470ebddbf94e58d7c11358cf139cba536cba2bad2c84f23e05e92e0cd5e72d5fee83b4506ba223386fd3f267d5ef23d80efca692e77b4dc91ac5fc3babe9566c42af12840a2b74d631f3e179353bf391f188f429418222e7d1af048fb25d2d2a544b641f83252fe96e9a58ee5afeac1e3eaea5afe9ca3c8364a3f28a66f26608d46cb6d6f3e7505c02f961d1e52fba6817875531021a028ab93b87ff9a0f2ba2ff8799290894c33a3f1a944124d7472c127f94414d6a19b3e831f963c9ff2f6f1c937b37303ce67118302f6b81d37de3b0aaaf27cbe3cdab6b43523d1bc8bc3456b85495c3129ee78f6f849d35f221972c42116f73bc0fc665feb502b6d9a6f88ae389433988e977cab994365ccaf380568cacea7c31cacd5aa2b97855c429352c9bcf49412814f4c9221c24b64822b9045dd2ce86379d0dcf641eba52b3647a54dc3770f7cfd55804bbdbfe044bece649a4402894bf4cc8a2d925614229fa5ae9ec9a3657595325cec8252ed208dc9d062480529b84eee3a1c8a96b31b5c83bd71b5627d589c774a093d3b50cb2649e39f1e116d88f8919d1bc51d6fca1bac784006ddcc00723055b39447c723f3510eec58e5286fa3539e0de35a91735c46b633996d9ce050e17056
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130594);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1915");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42306");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-cucm-csrf");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Request Forgery (XSRF) Vulnerability (cisco-sa-20191002-cucm-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a cross-site request 
forgery (XSRF) vulnerability exists in its web application interface component due to insufficient XSRF protections. A 
remote attacker can exploit this by tricking a user into visiting a specially crafted web page, allowing the attacker 
to disclose sensitive information, impersonate the user's identity, or inject malicious content into the victim's web 
browser. 
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-cucm-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d73094ae");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42306");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo42306");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.21900.13'},
  {'min_ver' : '11.0', 'fix_ver' : '11.5.1.16900.16'},
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.23900.9'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.11900.146'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo42306',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
