#TRUSTED 17657217cfad9fe9346ee27431a8d6e5c57d2bec8c8c93ddb194121d2561602ae2ad5ae8aaa5194a87b1f3166ece2a2abaf49be83a7e506bcc51591a97b3499afac557eea4a3e752f22d78507cd9090fd426683bb1c01db7d40f34437cefbc4da6ef7a0319271b3ddd56354207617a9893d18e07d32dea4ca6c5a52e2ab51d44c6cd20c94b545fe144018811feb6e0a3fba34bf2209ecf3c210b5e394d5fc2e1ca07d5e3dd278823bd3ccccce077b3dfe04a202a11ceea1f5819180a9a62fdceb1fc100b29305882da0dd0cab527c7531b338ac21773e215fdb708ea61587841ba91da155fd6071e2e2b7bc950ef1bf86a1becf4864188ce83eeff64dc11600cf0462f95f83fefe72db48382f87167f0fd8b3941e4af42547f851136f11c7472a1be465a88b4bbbdb6869e22915b9a04d07a364defbfa7eebe8f42314da3449a9b627e5a5f7804302b3b83bf7740a73375309f50d746ce3935767c89c8c2c6f0cf4dd4464529ef7e1b4774c2794aff22390d295275169e033d9e36b9a2f8ae8277e86189d552fe334ffea210278243c94ea266dfeed5f05277bb09c42aabc6947e6f8020beba36a51702db934f3930849460bdee0ec154d22890da735c410edfac6145f10e37434d33f3dddd36a7a2d26222dbe96d2e4d061da688cd35fc4f805b03e041c21e98f068317ac070486b1d5e05a05a63ac6cb8cee90fccf2a84c37
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131403);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-15990");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq76840");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191120-sbr-rv-infodis");
  script_xref(name:"IAVA", value:"2019-A-0429-S");

  script_name(english:"Cisco Small Business Routers RV016, RV042, RV042G, and RV082 Information Disclosure (cisco-sa-20191120-sbr-rv-infodis)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by an information
disclosure vulnerability in the web-based management interface due to improper authorization of HTTP requests. An
unauthenticated, remote attacker can exploit this, by sending crafted HTTP requests to the web-based management
interface, in order to view information displayed in the web-based management interface without authentication.

Please see the included Cisco BID(s) and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-sbr-rv-infodis
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b86d905");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq76840");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq76840");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info.model !~ '^RV0(16|42G?|82)($|[^0-9])') # RV016, RV042 / RV042G, RV082
    audit(AUDIT_HOST_NOT, "an affected Cisco Small Business RV Series Router");

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '4.2.3.10' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq76840'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV016', 'RV042', 'RV042G', 'RV082')
);

