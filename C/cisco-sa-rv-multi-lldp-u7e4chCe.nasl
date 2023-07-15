#TRUSTED 3e32ec1220a1123cb6fcd795b96c84b9223007989e72ed4d2559ed176fee684e3f9e5e0ada1287107d17fbd281c349eb135fc4812f5bab6330e7d85820e6a5423f4f0f063e8f21cc62ccf556a9cd877395cfebd26e57518581452f8577e1beaf6a6bfd844cf74a661ee0c58fde015ebd6884597c39ab374a49e85b1a3f8cc39e05811805aecc3b6f2e82c5185f1078643a8a86aec59d42803f87987160d9422a6a80907af3b3cb63bc067ebc45994b1b648fadeb3c5d9cd244b0e3bb85790e245f0de64c9f0976ca80059c8af8bec15bed5a881789ad69fa9866a0e1d2d55d729a9017367bb68d339114c2dd8a28365e8cad28821abbf8d11bba4c687ab815bb825fad8977c522716a50fc72a39b9d5afc4186fc9fe75533f284ba921615f0904e3b7cfedc6a2f4818ccd8b4af69fff604d1d616147aa344bb51c381e9ade65df252c2ea31e4d8d87161de03189a9f611494eedcb47482f960e09526797ad58661fcdac0c009ae384bb924cf0313fe2eb98ba9c68e217966894479a9d978a0e02ab3805e86c9b7c479be03dfa180ca54b8a6b391a913ac1f2d71e53d32d4987e601442653e938d0fb6ee1a07554cd7a00b38ebd503354babefd399e23ab98bea02b52832acd338e3f462bd06ce680fab4ec81bc548e8587bd417fe358b883e359f41be29d98c40d3af7d2a00163c50ac4e61cfcc95dfa2a353f0ac2373a631ac
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153257);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id("CVE-2021-1251", "CVE-2021-1308", "CVE-2021-1309");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62392");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62395");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62410");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62411");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62413");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62416");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62417");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw62418");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94339");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94341");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw95016");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw95017");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy01220");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-multi-lldp-u7e4chCe");
  script_xref(name:"IAVA", value:"2021-A-0161-S");

  script_name(english:"Cisco Small Business RV Series Routers Link Layer Discovery Protocol Multiple Vulnerabilities (cisco-sa-rv-multi-lldp-u7e4chCe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Routers Link Layer Discovery Protocol is
affected by multiple vulnerabilities. 

  - Multiple vulnerabilities exist in the Link Layer Discovery Protocol (LLDP) implementation for Cisco Small Business
    RV Series Routers. An unauthenticated, adjacent attacker could execute arbitrary code or cause an affected router
    to leak system memory or reload. A memory leak or device reload would cause a denial of service (DoS) condition on
    an affected device. (CVE-2021-1309)

  - Multiple vulnerabilities exist in the Link Layer Discovery Protocol (LLDP) implementation for Cisco Small Business
    RV Series Routers. An unauthenticated, adjacent attacker could execute arbitrary code or cause an affected router
    to leak system memory or reload. A memory leak or device reload would cause a denial of service (DoS) condition on
    an affected device. (CVE-2021-1251)

  - Multiple vulnerabilities exist in the Link Layer Discovery Protocol (LLDP) implementation for Cisco Small Business
    RV Series Routers. An unauthenticated, adjacent attacker could execute arbitrary code or cause an affected router
    to leak system memory or reload. A memory leak or device reload would cause a denial of service (DoS) condition on
    an affected device. (CVE-2021-1308)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-multi-lldp-u7e4chCe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?089c11a9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62392");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62395");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62410");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62411");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62413");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62416");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62417");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw62418");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94339");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94341");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw95016");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw95017");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy01220");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw62392, CSCvw62395, CSCvw62410, CSCvw62411,
CSCvw62413, CSCvw62416, CSCvw62417, CSCvw62418, CSCvw94339, CSCvw94341, CSCvw95016, CSCvw95017, CSCvy01220");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119, 130, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

var vuln_ranges = [
                { 'min_ver' : '0.0', 'fix_ver' : '1.0.1.15', 'model':"^RV132W" },
                { 'min_ver' : '0.0', 'fix_ver' : '1.0.1.21', 'model':"^RV134W" },
                { 'min_ver' : '0.0', 'fix_ver' : '1.0.01.03', 'model':"^(RV[12]60($|W)|RV260P)" },
                { 'min_ver' : '0.0', 'fix_ver' : '1.0.03.22', 'model':"^(RV340($|W)|RV345($|P))" }
              ];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw62392, CSCvw62395, CSCvw62410, CSCvw62411, CSCvw62413, CSCvw62416, CSCvw62417, CSCvw62418, CSCvw94339, CSCvw94341, CSCvw95016, CSCvw95017, CSCvy01220',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);