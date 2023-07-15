#TRUSTED 04de846855b021daf2af8a3aff8f037967252d7a36feb92ac897d04a95608ab0e9b80e628d7eda0df53c6507766cf9c761fb751afe60d6fba77023977a5b103fdf38e0325f6d4ef69eafddece5c5e5010055db3c5102706d6ac32ec9fb07ae32f6da4598c8f2058cdc11b70109eac9c0e4420a5a2d266d5f361d37971c58f4bf7184f8179c7daba15c2d08b1cd54946bd082adf4d7234c5165cd53c17e88b937e2c81acb94e6ba403d0b1988737187b51208a4d11ad7b4e480dc85350a1388f5851cdcc132d0d820bd8e7acec322fad70c6fc6c93d2efa8d23fb7be0a0aeb83d057472f76240da7d48e27bc929c72cdb9fe2957fd2893106c3314059e4f530f475b1022c43021bca5019f71577e7a19cd22200d7f3baea936b02691bd17037b2abd47578021c645b6e17ba34090beb443ad17b880336667fbc3c612d88bcac5335720c617c5a30b9cfe5869acd28732e8211ff6427132cb7a7c508a736cfbab0d989b51f43b504254f66dd9a4d4ae509fe86da8d39bc149455ffc9897ec1c1a115cac8a333a924c5c8209abbb09a28a8bfaf100d0d356d26b0c89d866d21830fc00d43229a02f41d7c10ef4d13f5ad150b92eadb7fc622c1376fb4245332b0cfa87f7aaed50a3fc027fb40479e3e4dd54386cce79a7d3268e68f84522004f23420d9c1e787ba0222b5d5ebafa071589d69c24f6379b1a2d02488de4a5dd79200
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160501);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2022-20734");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa32492");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmge-infodc-WPSkAMhp");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-vmge-infodc-WPSkAMhp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in Cisco SD-WAN vManage Software could allow an authenticated, local attacker to view
    sensitive information on an affected system. This vulnerability is due to insufficient file system
    restrictions. An authenticated attacker with netadmin privileges could exploit this vulnerability by
    accessing the vshell of an affected system. A successful exploit could allow the attacker to read
    sensitive information on the underlying operating system. (CVE-2022-20734)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmge-infodc-WPSkAMhp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4157d585");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa32492");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa32492");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20734");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '20.6', 'fix_ver' : '20.6.3' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.2' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwa32492',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
