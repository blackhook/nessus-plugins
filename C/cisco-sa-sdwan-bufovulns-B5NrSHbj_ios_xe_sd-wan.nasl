#TRUSTED 5db48424efe187fba5c1f44d29495e191485528861f05c6f8fec594a1e525d06acb551e22ec5c2ffe6aa7b2181c98f1517fa3e517dfd75f3ff415d0729abd0bae3b1f5d5836beb8a13970de04a71e717128d79e9a4a5b36777b0eff6921b55ac30aa46ae1a73650837348b62c8b4e78b0eeaf90a68b4527073dc6cf50706f980ef2374a3c00683506c482b610fa390ddf932df62e4275add7e63415fa5886693a545de917de0c26a6cc944819e3db7fd788ca40655ab25b9e8959eca39c646133d375a3b14837d58511c7d02e8c3be36c4165c76234284351cef72e144e05f1f4962ecba18a084a173acb3d392c6300b9053988c0233213f36963e5bd89acc34de9e87f8883f1b4b0690c196eb99b2d01026b0ae7ad52f9bf19b0dd7828caa6576c8aa4e373795107d3dff8a39e1c20a142e71eb45472ca619a8dce722e6be331658649c4ab41ffa7b9e380e304b553e8484fe69f269940497ed214c81c114cea33ae1b36f53835291128663c22a5bdcdc0b1dda549844fd1e3b073749b037afdb2a35e1d42ee22e6b3ef2c85ed5f78a18d35f791ea40a9376128d452103e6ae53a3107b7306eff8419a2566c005760c43fb67821ee86681476062d2604e654d490d4ccc895198749c3eee65460965144f19b4409400225547790a1845b967c33a8cae1f2f9230965746f956a2a25f898c9e4716772c62e80ae18fd8a26d20aa
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147964);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2021-1300", "CVE-2021-1301");
  script_xref(name:"IAVA", value:"2021-A-0045");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11525");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-bufovulns-B5NrSHbj");

  script_name(english:"Cisco IOS XE SD-WAN Buffer Overflow Vulnerabilities (cisco-sa-sdwan-bufovulns-B5NrSHbj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by multiple buffer overflow
vulnerabilities that allow an unauthenticated, remote attacker to execute attacks against an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-bufovulns-B5NrSHbj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f3f0159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11525");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi69895, CSCvt11525");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe_sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

vuln_ranges = [
  { 'min_ver' : '16.9', 'fix_ver' : '16.12.4' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69895, CSCvt11525',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
