#TRUSTED a3a095573f41912b577d3625b42a9fe3acf93e5a6506381e84248ae99ff4047b89719a63085dbfadebe12cfe00c4bd8161f2c88066472a5fd157ae927d28f288443c8fcb0678a5ff78d3fe12b747e90e21f18fd3bf49bfd7d8771927475f24716699c875cfbbaa4469302aa2cab149e157e339cad9348001fc7abd470f7e53cac027c355ac0bdfaa669419c5e127672d7857be6128678a748a78693ecca74700510124e5655bd26e5142983ebdf9949f3780b8bed0295bf659e8d533ea3d443bd78a986b50e292b00c480effbffe38cde74ea4c12e62133bdc313779c7934799ad02a64c92f1f1d21d0587ab9412110cab12747ec8f0dade357d3685ee6720e4891a6b9107540dceae01e63c53e498fe2bae53dbc33b218bc5b42a6f10d69dd47df72094bfe88f64f8fb5d7d3467afac31c9f1842e98269bab0da3478834bca57cdfc5f687b199bf9644bb4e5c3bdf0ed6425e395c39cebfe185f0aea8b7f5ec43c44a57918f6986c1b4565c38ec89a51a2e729da6f3ea73b379d8675c512f88cd0f7c968d4ffe81d5191ca93048e67e2102bc3246cbcc4152eea7e232cb794d860db96f8f8c8367160031c6e50ff20c9e7f31011f263adc34449d7b3b60987aa94b226375a9f439545821cf64e7a975f3f01344f34ba733747e272f88405e36bb257145658a3a060089730b692bdf26b9716d88bf89a2adff288135250c5a72
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139664);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3323");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr97864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr97884");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr97889");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-rce-AQKREqp");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers Management Interface Remote Command Execution (cisco-sa-rv-rce-AQKREqp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by default remote
command execution vulnerability. The vulnerability is due to improper validation of user-supplied input in the web-
based management interface. A remote, unauthenticated attacker could exploit this vulnerability by sending crafted HTTP
requests to a targeted device. A successful exploit could allow the attacker to execute arbitrary code as the root user
on the underlying operating system of the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-rce-AQKREqp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aefecfc3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr97864");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr97884");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr97889");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr97864, CSCvr97884, CSCvr97889");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3323");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");

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
 vuln_ranges = [ {'min_ver':'0.0', 'fix_ver':'1.0.3.54'} ];
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
  'bug_id'   , 'CSCvr97864, CSCvr97884, CSCvr97889',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

