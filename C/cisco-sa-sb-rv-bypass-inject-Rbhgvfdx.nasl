#TRUSTED 325966a4e392a09f3ff79958415c109d7cedfb1584b4f2a920c2012c94d71ba2ac7cc6be571027e4baf408851865ef13bb4f6c5f85feaf777c3a4cda1f450cfdc1f9d4b2ba410a7d667bbadcf62f2c9bd29f37557182b88e5c3b97ca4acc7f2489839ea48365fd6486e4bf5731f0acd3a2a6fbac65427be8dfc2009b31ba496adaf90b6fb33e2fc4202e06bc56e3c529522754fa48fb106bc40f437c9d37c05db54a058f7f06eb6d77f18b2b6222f3195d263c25c72363d74ba170136e848836e3557f67f5c31a67a692a1395c57690a1e272710b4ae3a4e666f8bc20b58147fb009d5ab881dc6e9e997d12d0f60e6de8a988f8a546b7232d10f9e2ffe0b4055ef905dbbbe57739018641989ef8044af8898ad83dc41d3c8e0b4b419859c28a2d93c7538c7786160b98ab5ba5bda8c0bea7039678bb5a6d78a983df638afbf060381779dd9b35cec4797c1ca78772869cfe2dbaeacbf269f4e13633c50d10faf2b80e896241dd0744d607a4ea92f80f1180cef19b1262d8d97caed4edcc29c1676556e969da379aca63b65ef94ca8e419874a8c0e6baeebc15b8b9bee4612a171d659377d1c6cf1b3ba64b68bab626091185c4f6e97f3bc6ce0dfa22d500163931f016eaf3fbc439ec7dfe7699f2e668a7de23e494539ef29db954f1882a7b97c76bb9eb67c25c3e3d21aff4b9a25f3afece378800a8b54dae83dc5893464cff
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148652);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id("CVE-2021-1472", "CVE-2021-1473");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw92538");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw92718");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw92723");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv-bypass-inject-Rbhgvfdx");
  script_xref(name:"IAVA", value:"2021-A-0161-S");

  script_name(english:"Cisco Small Business RV Series Routers Multiple Vulnerabilities (cisco-sa-sb-rv-bypass-inject-Rbhgvfdx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities in the web-based management interface of Cisco Small Business RV160, RV160W, RV260, RV260P, RV260W, 
RV340, RV340W, RV345 and RV345P Routers which could allow an unauthenticated, remote attacker to execute arbitrary code 
or escalate their privileges on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv-bypass-inject-Rbhgvfdx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8b63db7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw92538");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw92718");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw92723");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw92538, CSCvw92718, CSCvw92723");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco Small Business RV Series Authentication Bypass and Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119, 284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_routers_vulnerabilities");
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
var model = toupper(product_info['model']);
var vuln_ranges = [];

if (model =~ "^RV(160W?|260[PW]?)")
  vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.01.03' }]; 
else if (model =~ "^RV34(0W?|5P?)")
  vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.03.21' }];
else
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'            , product_info['port'],
  'severity'        , SECURITY_HOLE,
  'version'         , product_info['version'],
  'bug_id'          , 'CSCvw92538, CSCvw92718, CSCvw92723',
  'disable_caveat'  , TRUE 
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
