#TRUSTED 5f21fbfad42498912b63c67c645a0043f5cf7cbd6736bbaa107b8008ee3cae44ce8ae7d9012a3af1213dd79ef85c7d41094fc40c5398d5198d87118887c0a134ebe726646a575aa2aaaa1a9468d5ca3cb7714f962b2f041c55a2b6f79889b13cd05c8741ac63e9b8326e517638741180d86fe43af3a8057ec0e2e44c9f4458d7d86a48364015c5f22d311f9d9e035a50f78fb1549f5c18524b7e53d8a70ea7f1c4aa1020e0de67d886251afa1ae0b097e37666db61a0629e845a991490d46ad22347cda3c228c421acd137de5f54effc65331fe0cbfd1dda9e70c91204ac04015f2bea10a4b3e67c8cc20fb607f4a26bc1329de57863971ca8417b8da37cc2ece76b4a3c37667cb23c93875bb9c9a7e01fee2d58266f179c7a3aa2ef113762d1273bf85abba731da7a5b0c400c0ff2f06881a768c9d702a7fa39b63b6e5f88f2bd82e571ea0b7722bfaf35dfa05194ce3bba91b567bad68bb75ddd19338d6185a8e4d1752891e358bb6a1ccc755851c76cc3013645e368a5fbf5da70a52fe890d527f01b6df5d776431948997e8cff7bfd2042a756450b1279846f1f14c1980f129382e2213c01edf360e97cff25c6ef4e72a0bc5ecc1a3c85e58a1c469a913e1759cf0ff614049623fb1526104ea7d189b80f47e8f25eff88f6b175f6ceeb6fa018761064d0a18c3ff3f6b44f1d2b96706ff4615ad3669354b9e3b6e946a80e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148712);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1413", "CVE-2021-1414", "CVE-2021-1415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv34x-rce-8bfG2h6b");
  script_xref(name:"IAVA", value:"2021-A-0161-S");

  script_name(english:"Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers RCE (cisco-sa-sb-rv34x-rce-8bfG2h6b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities in the web-based management interface of Cisco Small Business RV340, RV340W, RV345 and RV345P Routers 
which could allow an authenticated, remote attacker to execute arbitrary code with elevated privileges equivalent 
to the web service process on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv34x-rce-8bfG2h6b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85f4188f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94030");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94062");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw94030, CSCvw94062, CSCvw94083");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1413");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(502);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

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
  
var vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.03.21' }]; 

var reporting = make_array(
  'port'            , 0,
  'severity'        , SECURITY_WARNING,
  'version'         , product_info['version'],
  'bug_id'          , 'CSCvw94030, CSCvw94062, CSCvw94083',
  'disable_caveat'  , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
