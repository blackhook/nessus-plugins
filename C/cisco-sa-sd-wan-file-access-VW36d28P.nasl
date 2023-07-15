#TRUSTED ad79487963b645fe8e84973085b228642fb6051eced81fc1e463805ec9d982179183d0ba0d2f237a02987469c1973c439670549b714c5d41ab591e4832683b3e418354b9fa2fc5aed3a744bb9624da471cba14d2a7744a8f2df373dc9783feb4157b08fda4373ed78e4c933e4c811ceb090adef49c916a03c49e5286746054c9ddd2dd48295dccf465dfefc93956b30209158ad27a804cdbd1b27ac5167afb783538c4f795ab021475f54269d3800b03e23b19abea62e330fb50ead8962f516f3f66ce2d84ef1462936e1e0a96579d1df9bccac84a76dacbd9f8652111404be054da0e75983f1db42a0259c2b5d8ec6d294ece040f0b4d46b50b3eb5d8a341b89220e8660216d824591f7545b6345daebae36b583b9833765b977cdfa90af1e303b6f9ef28d3503e2b8848b102d777249417152a1a28dea4e4c79975ca35381d15e319ea46cc00a8b8411fd75326e9597cbcf5ba180526e6734925388520543653fc8ee24591ca829a745055ad04b4e5290325403a86841cdc40cf3897090b13ec74cefa962a3fdf9dbaf4ea593f8717b209d4b619ecd578670ee3d5008f2e07ae48dd36d26e2887eee9bad98c625055bae03f5c0eb7d09e537ebc17086f0e84b8554f8361007a23d9dd03f606c51443ff3c2a2771601531be25c86b9a27e2d179f0c9eb9fb35da5f2721e8d4d66404fc4c72b5f7f0cceef49fba687d2c8bfef
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159718);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/13");

  script_cve_id("CVE-2022-20716");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy11382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-file-access-VW36d28P");
  script_xref(name:"IAVA", value:"2022-A-0158-S");

  script_name(english:"Cisco SD-WAN Solution Improper Access Control (cisco-sa-sd-wan-file-access-VW36d28P)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to gain
    escalated privileges. This vulnerability is due to improper access control on files within the affected
    system. A local attacker could exploit this vulnerability by modifying certain files on the vulnerable
    device. If successful, the attacker could gain escalated privileges and take actions on the system with
    the privileges of the root user. (CVE-2022-20716)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-file-access-VW36d28P
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f70bc151");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy11382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy11382");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20716");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '20.6.1' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvy11382',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
