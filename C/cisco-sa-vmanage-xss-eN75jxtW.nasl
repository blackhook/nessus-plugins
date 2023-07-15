#TRUSTED 4aa630ba2724cecc043bc1bc77afd96c7ba1b08d1a96df99965aad1a44293b44afbbd9e4c112fb0b57ca63a83ddecd4bba9bf737c4edf853c81ca2af2a10b2d606d690a28511423a572d5ff9a4ab2a6ff82cbdafaff5798a16961870a5ffb356827b43c8c14fa705d8fd6b95e755669627e2769f52311fb9565b73faacbb6bb3fdca8ff82e39e152fb1df76e1d42f479dcbf1e676c43c5e7567ecff73a85c0544ca8a24b42ada1730a6e3b5ec410c010433115774953f36faf2cbf1a7cdac75be0ce3feb4d1844985ac31a4acc38d85452a97adbdcbff93cb9a252cbdf972a532f487936b015f5625a4f0245ae5db14bb14fafa387a11d7cd5b7cbca4cfcbf9f5c559fb0756a4ed397b1f4e7fd229cddbc79726d179e4b29457759fac0cbb74acee8cd3d4135a9750ee9f7066f585374a9695f161df8e793666aad4d5c6934a604e207b1bed902d85c49a60674800e0ba7d18fbb24ca9dff62ffa10c5e0f24d8719fd62df296345844bf4721867d88e02e0af3a42c5d8a9871ac8d2920ef9d1419abab8cb441a01d0095b95a9872d900ef359a9b73646924af87cee528f4550c759c100046460d6e11c97a6fc47743a535e3fce7b316bd28ceae14e3044e5fe24fc1274e40df6b7694ffde686b361be66330dd533d99d38dcaac6a44743dc9b1cb2e16b563d893878361bad28c93b6623c558c57781f0b391e79da1e3412ecc0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149328);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id("CVE-2021-1507");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28350");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx24115");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-xss-eN75jxtW");

  script_name(english:"Cisco SD-WAN vManage API Stored XSS (cisco-sa-vmanage-xss-eN75jxtW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a stored cross-site scripting
vulnerability due to the API not properly validating user-supplied input. An authenticated, remote attacker can exploit
this, by sending malicious input to the API, to execute arbitrary script code in the context of the web-based interface
or access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-xss-eN75jxtW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efe33193");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28350");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx24115");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu28350, CSCvx24115");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1507");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];

 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu28350, CSCvx24115',
  'version'  , product_info['version'],
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
