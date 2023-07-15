#TRUSTED 9859b74b70ec73ebec0428e2ef97b177c8c55619807b9ea56b7cfeb0172245558c97a1b60ffc1ff9c2b5c4681665949a39d0aa20968ce963932a71d0051fefbcae6cfb3655a2d91edba7c6afae95bf74b56d126a05ffd901ca41b663ac948852017f60220e63b2a70c31e3d8c7a37e5800d5dc483c4b7bdd998dd200ee6406f7fa97f06d88c0cacb33dc45042aa39fc5f58241ec4a52ec121df20f68f133588e2860407377dff54a25ed5291a3325626c05b2745b65c62c773aab0992276c73835bc255716cda19ca9fdf0587569014d776e5a4c8dcf1312765a19914b94db6e79dbe2b288a5b10dffb859a48cc010a8dac129a944205928dd4834ce45c742701d337fcee2ed91c8eef2145680c85f357bde273603337506e6ad7b5876f4efce6fd05e4bb6aca5639582efda5063cfa2c5bb10e24f5c85d490ea6b1b34145295785c3c2edfaef8f767abed7318d0e36a4991dcbcae1097ad9ed7aa64e1a2b304d52f0faeed267deb7bb3ad95a5a1e7c0644fcdd76c60ea7708f2ea2955b77e6462ff6164eb461fe2e603300f1239a57650924ff1df2093f8a32e1912c072b40cbbbbc26cf59187392b82bf49125928b164edb6825842cd6069ec9580e621969f4d2fb052fdd3406c1058824140311804dcde4ed76a375afb78ac2675ff20b734b168e85acdc2b6981a2c70982012fb00b3591fe2c53925e07a6e584ad6bb911a
#TRUST-RSA-SHA256 662a54be34a7450028d0a7725c47682bf216dcfebe02b1af47dea07cf454a1f454b241a6a59b040b12b713bc4b03b48ca5ba081f4a78b94cd8ed0f9e644d8c6d6a092e89adeca9a80f8faa8112473e2e0245ca5bcfc1346847c491237487dc79033cfb938d165f2b719831ca2fe84d164274ddb9ae1959a155d19403d0663bf854e963ca9a36a86f2394d26e98ea4278079c1287b9f15780e50243bf5372d9cc36d180a4750808504a2342ec5ee71c761ee08501e61945fe9749eda37750e6c572dd9871970adeab876e946d117fe4d893ca14c9cca299662128da99d4ad79c1cd757dc175b878394b529fc3ca2b9af7c10e4bb382637175c4b71204e6f3ee1bfb642e92a99435dd936d5542d0df3ab989b2c32fb0e68b4623c45e9071f11d6ad059d0642ba80bc5953e7cc71a889c2d323eddc312f91c537f9d372356ff1a663e315cb685598f4de4d45a0a40bb2ba7df14a0b54ef82eb9cd3cc232c46a83de747371410b1c0e05e8ccbf90fc95b191f5a889d8195b3f9b94de3cae235e07b86003a3dce35186e26861fda529abd34ad13b2f8b4cd5f098bb124583a5b56b4aea1c0f8af91f5fd3adf7c7a99816af7545c49f8e17858f92c2a6c842e7f8c819e1c68d2f04c582c22a3e47a4c71240a3539f90b4a7a52e2575e7256559c95fa0b5569aff4f4127dda7ef36d99afd85a8831c38cfeb826bdbfb09fe8bd61e6ee9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152212);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-1609", "CVE-2021-1610");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy15286");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy15342");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv340-cmdinj-rcedos-pY8J3qfy");
  script_xref(name:"IAVA", value:"2021-A-0360");
  script_xref(name:"CEA-ID", value:"CEA-2021-0038");

  script_name(english:"Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers Multiple Vulnerabilities (cisco-sa-rv340-cmdinj-rcedos-pY8J3qfy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-rv340-cmdinj-rcedos-pY8J3qfy)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities:

  - A vulnerability in the web-based management interface of Cisco Small Business RV340, RV340W, RV345, and RV345P Dual
    WAN Gigabit VPN Routers could allow an unauthenticated, remote attacker to execute arbitrary code on an affected
    device or cause the device to reload, resulting in a denial of service (DoS) condition. (CVE-2021-1609)

  - A vulnerability in the web-based management interface of Cisco Small Business RV340, RV340W, RV345, and RV345P Dual
    WAN Gigabit VPN Routers could allow an authenticated, remote attacker to execute arbitrary commands with root
    privileges on an affected device. (CVE-2021-1610)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv340-cmdinj-rcedos-pY8J3qfy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5b4035e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy15286");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy15342");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy15286, CSCvy15342");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 149);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340w_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345p_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340w");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345p");
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

if (product_info['model'] !~ "^RV34(0W?|5P?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.03.22' }];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy15286, CSCvy15342',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

