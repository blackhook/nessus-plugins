##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163883);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-20827", "CVE-2022-20841");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb58268");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb58273");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb98961");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb98964");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-mult-vuln-CbVp4SUR");
  script_xref(name:"IAVA", value:"2022-A-0308");

  script_name(english:"Cisco Small Business RV Series Routers Multiple Vulnerabilities (cisco-sa-sb-mult-vuln-CbVp4SUR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities:

  - A vulnerability in the web filter database update feature of Cisco Small Business RV160, RV260, RV340, and RV345 
    Series Routers could allow an unauthenticated, remote attacker to perform a command injection and execute commands 
    on the underlying operating system with root privileges. (CVE-2022-20827)

  - A vulnerability in the Open Plug and Play (PnP) module of Cisco Small Business RV160, RV260, RV340, and RV345 
    Series Routers could allow an unauthenticated, remote attacker to inject and execute arbitrary commands on the 
    underlying operating system. (CVE-2022-20841)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-mult-vuln-CbVp4SUR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93fea3b4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb58268, CSCwb58273, CSCwb98961, CSCwb98964");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

# CVE-2022-20827 and CVE-2022-20841 affect the following Cisco products:
# RV160 VPN Routers
# RV160W Wireless-AC VPN Routers
# RV260 VPN Routers
# RV260P VPN Routers with PoE
# RV260W Wireless-AC VPN Routers
# RV340 Dual WAN Gigabit VPN Routers
# RV340W Dual WAN Gigabit Wireless-AC VPN Routers
# RV345 Dual WAN Gigabit VPN Routers
# RV345P Dual WAN Gigabit POE VPN Routers

if (product_info['model'] !~ "^RV((160W*|260[PW]*)|(34[05]+[WP]*))")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router'); 

var vuln_ranges;
if (product_info['model'] =~ "^RV([12]60)")
  vuln_ranges = [ { 'min_ver' : '1.0.01.05', 'fix_ver' : '1.0.01.09'} ];
else if (product_info['model'] =~ "^RV(34[05]+)")
  vuln_ranges = [ { 'min_ver' : '1.0.03.26', 'fix_ver' : '1.0.03.28'} ];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb58268, CSCwb58273, CSCwb98961, CSCwb98964',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
