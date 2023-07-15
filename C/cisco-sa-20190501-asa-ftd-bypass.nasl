#TRUSTED 2f3bef01287f56f5d1be577e6d2e0c8d08992382488cdf00d71e39fc0a891f936a14bf02e616fc2c3e1274f9731e9eae1362f9cecdfba13f4db87695ffcc5a091111e59f9a4308525226503750932b8539b5d833b6d3521823237ac44d05e78114637e23e167dc84f7e3201de58f025dcaf54a87b26e88e5aab12060b123accb7bdf89faef896269d1dfc0cc05f4dd0ab60321f015d98c16ea60e1435b78a333e3217594ccab094da3ea6b5c6c7f618c4ea4c1e58650ea1ca4565e278eb9a97acd437ef874a5062e518f962509d2110685d838e70fe6915074c3bd0f47613c4f2f4d18b743c9ceffb456f7f47b86f316ddc1d8831c5650276c43ce97e5a7283b76a8da86d186bb8e95e65ec558f020a286e6c87c02ef360bb26f9179730131fc77082a9eecd3f1811bcf9b6b4a50d885116fa7d081ef1afa4db5e8ddc67b3750db91cae0db0a57390a650ed15b7f554d922ab9dc4ce72710266955c885758994e75bd2cc7b0fdc0661a5175f2449df5a1825badfb77b763a0be64c219eb8aaa49ec27ddbba9e1e4522e2d09276c44d86e072dede00441a2f10213b2dd2b8096fb3a3662d7a637a75faa26b3794372256ebc2e4e566ccb87cba774814fbd7b7e30c4f4c005fd96d6508f19b04443969cbf276f440e475a3749da1835e974a97e3eee7882a7d94f3e2bf01e03fcc4de4ffed9bc750b0caad7e74eebb5b201ab52e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137235);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/10");

  script_cve_id("CVE-2019-1695");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm75358");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-ftd-bypass");

  script_name(english:"Cisco Firepower Threat Defense Software Layer 2 Filtering Bypass (cisco-sa-20190501-asa-ftd-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in the 
detection engine of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software 
could allow an unauthenticated, adjacent attacker to send data directly to the kernel of an affected device. The 
vulnerability exists because the software improperly filters Ethernet frames sent to an affected device. An attacker 
could exploit this vulnerability by sending crafted packets to the management interface of an affected device. A 
successful exploit could allow the attacker to bypass the Layer 2 (L2) filters and send data directly to the kernel of 
the affected device. A malicious frame successfully delivered would make the target device generate a specific syslog entry.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-ftd-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f0a37bb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm75358");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm75358");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense Software');

vuln_ranges = [
  {'min_ver' : '6.2.1', 'fix_ver': '6.2.3.12'},
  {'min_ver' : '6.3.0', 'fix_ver' : '6.3.0.3'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm75358'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);