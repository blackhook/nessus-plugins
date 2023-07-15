#TRUSTED 052d4e48a1d5007306a85bcd85a353f2c8c14e6bd2e126d33eb229810cb53c78652f710254d5e6b0f7d7dd3579f54f3c25a3ea68824693f7ca8bca0182e68d223d2a7071db6a4e3ed02bce63969bb4cffe24b8356c789eb28fe9ae1d0ff0ce9b9fd5e684fcbae95cbef3e63a44fcacae793a7d8755905636aa37090a72e2678762688019c60d6ad70c70ed94731b6585ee8bfc103b871cfd44ad65c19daa49c00fb422418ae5c8bc742bb67bfc6ec3e21a152e962bc0794460e4560865f0bafd8b347096c3fdf56a07a8afe7df59ec5cb99a30022c6464f725458edab1137eb46ceb11a047f233d8e62ba80e3959e0b8fe9fade088f2a37beb718c6f55f49d583967ebc230b0cde74d9049e1b9306a62af5da34d86778cab888e5ce66503fd8edd960f5a560d5955d65661e6455afab4a8301346d7d9662a17b3a16bda5f0c712747830e23084a76bcb34b765cd895de5a225717d16851b012a4154da179ee46e7835b4ef35c5aa90f1b8e2c35fb05a98b5e7d2e01bcd9c37bf764fce57924e81a9d3e088e90255590c9576fb344788c3fd3005febabfeda0b4a540ce7ca5142d463c09eeb3006e624cf8a6ca4d5d1e738465469f3cc0188960b6cfc0caa0dbc71efe01b517b12b2520623285b08d20d7f99faf7095963f692cbf6ce5d4ac6522e7988f6583726c36f46e3c275f72f4e1fde48972c59ecfe9d5c3b1d618aaf9d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138587);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3144");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96247");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96252");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96256");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-auth-bypass-cGv9EruZ");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco RV110W, RV130, RV130W, and RV215W Routers Authentication Bypass (cisco-sa-rv-auth-bypass-cGv9EruZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by an authentication
bypass vulnerability due to improper session management on affected devices. An unauthenticated, remote attacker can
exploit this, by sending a crafted HTTP request to the affected device, in order to bypass authentication and execute
arbitrary commands with administrative privileges on an affected device.
  
Please see the included Cisco BIDs and Cisco Security Advisory for more information.
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-auth-bypass-cGv9EruZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?763b9441");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96247");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96252");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96256");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr96256, CSCvr96252, and CSCvr96247.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:small_business_router");
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
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

model = product_info['model'];

if ('RV110W' >< model)
 vuln_ranges = [ {'min_ver':'0.0', 'fix_ver':'1.2.2.8'} ];
else if ('RV130' >< model)
 vuln_ranges = [ {'min_ver':'0.0', 'fix_ver':'1.0.3.55'} ];
else if ('RV215W' >< model)
 vuln_ranges = [ {'min_ver':'0.0', 'fix_ver':'1.3.1.7'} ];
else if (empty_or_null(model))
  exit(1, 'The model of the device could not be determined');
else
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr96256, CSCvr96252, CSCvr96247',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
