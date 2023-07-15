#TRUSTED 84e10f10e3e7f7dc91b6d689f36365888277100097322c539af558ca08c89facc3dabbfd0102ee0c4a14b5d46ea8a31c4844af7b15c8a7bd0c43a8022f740dede7d1a7c3a416e787311dcd6800d4a6143cfd4d6b86c37b005e9067cb5265e54580dc53a110988d849495b31b3dd25edd23e500a0eca6c1b29ab6aedca6788b7e5003eeeec29dfa250f3ed1918d9a33e8a36f4cb340576aa12b765cceedaf26a73b83d6383cb508cfad5ed50e1ece256705adff732aa8072b1d46204f22aa2ee0472add80648b9e9d544c2fcad61d8f2b81e1733a418b5d92e748d7e86d2cf33d7497d099db5b51c94b1ef7e465c865a9643df7443b6fb0b8a118a70d6a8ac35fc7bd44471c0f77539c399078d03327e8934ac615493c2cb249a2ffcf7dedb3fe1f0acbd7f077dfb91dd5dc899289f43aaa9a6f74e402fad236a20bcd343a442279d7b1059b4cd4740db969bf41065076aca0615285f54378932c1d75a00710103dd49d2c294442e2d4a198d5096007de168176590723d7c44e7daf5c8baa3f9a3913c24e28f16084635dd7ef01be5f136c2e4b319c0ae8a7bf7024de160d9661bdab4abcf6da2913051b8ad7626e67d0be5413b8cd50ec1e8e1f80a6b709ae8f6506041eba06015d5e3e32bc6f108b1f3da1bdbd825b90eb1a4d3f1c6b396450eecea7339032cc20f99f5329cda5d936a667cc582549af1058ed7f353a621c88
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146267);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id("CVE-2021-1296", "CVE-2021-1297");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19856");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw22856");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv160-260-filewrite-7x9mnKjn");
  script_xref(name:"IAVA", value:"2021-A-0063");

  script_name(english:"Cisco Small Business RV Series Routers Multiple Vulnerabilities (cisco-sa-rv160-260-filewrite-7x9mnKjn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple 
directory traversal and arbitrary file write vulnerabilities. An unauthenticated, remote attack could exploit these,
by sending crafted requests, to access files outside of the web root or overwrite files on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv160-260-filewrite-7x9mnKjn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0028d4bd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19856");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw22856");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw19856, CSCvw22856");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(36);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

# RV160, RV160W, RV260, RV260P, RV260W
if (toupper(product_info['model']) !~ "^RV(160W?|260[PW]?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

vuln_ranges = [{'min_ver':'0.0', 'fix_ver':'1.0.01.02'}];

reporting = make_array(
  'port'           , product_info['port'],
  'severity'       , SECURITY_HOLE,
  'version'        , product_info['version'],
  'bug_id'         , 'CSCvw19856, CSCvw22856',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
