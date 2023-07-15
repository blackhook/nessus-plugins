#TRUSTED 8d1e25eac9311fc30f5a9a94c268eb9a5f8efac23e47077b3ab2a0e35d959b70cf1edba376f025c0ef91413f9f3086f2a978ad409bb5ea2d2b6b2162a4592c84bee3aa0de2841c7c0dbf57b5cd576329c822d002efcee1a92c9e34399289db8e5f9964fc76038f0977c44d6ba2abd2668c785ef6db681793770fa15ce7001c1e3c7275d03166802cdf34d570bb0364d81f242438342599f095ac4f36cd3dd1b4d221eb2ddb24e115fa67da26c9256fac6e628335962d72e7a39466b8518495a2090bc658d0a0184f61ec6c2d1f660fbabacd61606abaaa9e7e2e5092ee3e64751164c4a5c3e6d504f23485ca606d75788f28afc8b793f398fa7261f422b457405485df951f2e97b061aec009b4f3c4aea0185fb127bc4ded6294cb939f27d77e6106b8c60d0ece1ed750ea4d6ad8609c48cf101b1ae5ff19b8f772c419dc8f40e7c9ef1d20e291e94c9bf2ffeab5e135308f1b67b0a346bf64f9b3bb573ee096f9b7ae742c02d080729f9025cc670f2542f805217b209f81a5d537dd352282255fa4422390bea93ca4099830069ba92228196388f6367564303915242f19747799f0179a242d78fe79b2948a072b0ad15b53031667b8a988e672c37d2d878cc545e3e58c7e996ebdb9547c801ff1b8be6bd1d738364b13612ede1e2f64edad7b086ce424debef506914723566c8b9ee904ecfa4251826c56d1a25e0945a48e90
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141467);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id("CVE-2020-3268", "CVE-2020-3269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28203");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28218");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28229");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28233");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28237");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-routers-injection-tWC7krKQ");
  script_xref(name:"IAVA", value:"2020-A-0274");

  script_name(english:"Cisco Small Business RV Series Routers Management Interface Vulnerabilities (cisco-sa-rv-routers-injection-tWC7krKQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities that affect the web-based management interface. Please see the included Cisco BIDs and Cisco
Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-routers-injection-tWC7krKQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48a716f1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28203");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28218");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28223");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28229");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28233");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt28203, CSCvt28218, CSCvt28223, CSCvt28229, CSCvt28233 and CSCvt28237");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3268");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info['model'] =~ "^RV110W") 
{
  bid = 'CSCvt28218, CSCvt28233';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.2.2.6' }
  ];
  fix = '1.2.2.8';
}
else if (product_info['model'] =~ "^RV130(W)?")
{
  bid = 'CSCvt28203, CSCvt28229';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.0.3.55' }
  ];
}
else if (product_info['model'] =~ "^RV215W")
{
  bid = 'CSCvt28223, CSCvt28237';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.6' }
  ];
  fix = '1.3.1.7';
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');
}

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bid,
  'disable_caveat', TRUE,
  'fix'      , fix
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
