#TRUSTED b205293418a8afeb3592d051cf90b8583ca5bbc2134d5625d8e8825ace67532a34eac8e69b21c072292b38598bd39b4cfd8a6efc666c35666618bb3f4c1a72f7d89c7161f741e088ebffc9bc905c5dac252382e380ada6b6fb6ac202e2b1585b0d554022ec0f43431b93559d7cb9df9b6e24b51571eb9a4f6fc87571b84509f342f2fb3ba214c16de5d51a265e771cf317fba6687d47c1d32810ee6f72f60ab7fcb76ae4e3815bc68fe6700d4690baf1abf017a89f899d185cd79d7d01bc87f9e1cf6cb7ba79177e04313ec00154896d5212ad7d229589e9fa7342ec643a91d98f90c10c56dce6db2cac5dffe875e6527dacf0d01ff1f10ba6c6aaf9c9c4b9365a3b0c5eeadf1b89466cd6d1d207c37c493b6bfd7ca4d0851f3d4e702c0372b5a51e5e52bdbe0a7ba141e2f1efd55ddb5f427781ac94418cf46f8c85a1f054ba799fb837906cbc4fc2e1c71f4faefed24be38da868c0e8bea86caae6307f1fe9ef3f254a9f4b31a467c5fefff8a3eb2d26806d625ab8c8a576fe1fb96ea1f03066a59e29be2db136e76f9c5cc35d157536c1202130d90b6d5aeec1d62406931c0c8d595d595d166ca213ee1a890d27ff2a5349a347850de032a3b2ed94890eb8ac4dd1d93b87818fd8ac0c311e754a226732f7aa941b4dc5e6b236bbcc162cbcbcfa5049d55666aa38989fb51f8ddc3504c84ec8f40f7ebd51b24f0bc5ca0ee4
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143150);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2020-3470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu21215");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu21222");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu22429");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu80203");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucs-api-rce-UXwpeDHd");
  script_xref(name:"IAVA", value:"2020-A-0543");

  script_name(english:"Cisco Integrated Management Controller RCE (cisco-sa-ucs-api-rce-UXwpeDHd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System E-Series Software (UCSE) is affected by multiple
remote code execution (RCE) vulnerabilities in the API subsystem due to improper boundary checks for certain
user-supplied input. An unauthenticated, remote attacker can exploit these, by sending a crafted HTTP request to the API
subsystem of an affected system, to execute arbitrary code with root privileges on the underlying operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucs-api-rce-UXwpeDHd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e999cbf5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu21215");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu21222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu22429");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu80203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu21215, CSCvu21222, CSCvu22429, and CSCvu80203.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Unified Computing System (Management Software)");

# Cannot distinguish between [CES]-Series
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '3.0(1c)', 'fix_ver' : '3.0(4r)'  },
  # All 3.1 vulnerable
  { 'min_ver' : '3.1',     'fix_ver' : '3.2.11.3' },
  # 4.0(2n) is fixed for C-Series M4, but 4.0(4m) is fixed for others
  { 'min_ver' : '4.0(1a)', 'fix_ver' : '4.0(4m)'  },
  { 'min_ver' : '4.1(1c)', 'fix_ver' : '4.1(1g)'  }
];  

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu21215, CSCvu21222, CSCvu22429, CSCvu80203',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
