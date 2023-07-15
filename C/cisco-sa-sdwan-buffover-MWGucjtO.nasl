#TRUSTED 6bea9fb63036ce42fe9ee755a80aad99489f41c5ced9364878105d3ef1b30a62bd2b2902e21f23fcc0dd2742feea3b1b0c5be8fe1d29f5aa635e28fb58b2ae64c5a2e6724a2bc8a62752f786393397bb8757c29548dbf9cb73b7fa698c8f12249927444c2d7d51fe1bdc3954fabc8009cdc2bb5c0f2f1923e7f9d88e7fe4ef6832e4435523a806c2036841b18de8d436c56377809114841ed72f2eb057c920af5f5a2d92f086c9702943d185ef9a5ef840614eba543656e53df469ed3096140b589376a2acc51a443cd90db13e8bf9e37595bb70d995384e493804e966e60893ec7b406947d246208a8639508b1a183768478edfc1f2ee14e93620bb00222a1278a2b6df42ac6894ebc238532344035a0054a41577812dd8ab610262a6e60e7502b5d834109db9fcf610630b10315916285abec14372d1f81809d3afe2b0ee2629411bc494a032ed19c7c614334a954ad980600506f84ecd77ecc796eca2336d68134086a41af761ecd5cc6c00f3054dbd33cb622d2abbc8bcccbd8246c7682216a46ce38580f0a67fd72a0370f37a7669ebfe8af902e4891b79ad70a279938aafc45ead812827c225dc2f2d6102c4e2accf289885026484e4834e2a828f55c993bc26bc8bed92ad0f7ecaa0d63f21b643bbc785fd058b93a323d90bd9bc946cfbe106692b96e57230128d7ca2eefabb90154c389042aee6472701db6eb19db6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150992);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/01");

  script_cve_id("CVE-2021-1509", "CVE-2021-1510", "CVE-2021-1511");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11545");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28407");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28442");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-buffover-MWGucjtO");

  script_name(english:"Cisco SD-WAN vEdge Software Buffer Overflow Vulnerabilities (cisco-sa-sdwan-buffover-MWGucjtO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by multiple vulnerabilities. Please
see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-buffover-MWGucjtO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e35fb5b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11545");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28407");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28442");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt11545, CSCvu28407, CSCvu28442");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vedge|vedge cloud")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.4' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvt11545, CSCvu28407, CSCvu28442',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
