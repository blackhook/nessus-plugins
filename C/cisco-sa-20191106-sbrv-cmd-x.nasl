#TRUSTED 5fce133dc0615c8be98711753090a6f477d137acb807e99b5a07f61f958f26abc1e64bb5284a34c7c9a31e2a014c7955a4ffaa2e52d7f56f4536dc08587caea7dcbba8cf732167753b3e834073dbf180b74f1e1b7f82af229d32e7f8659da72eeedbe311c755c76ca71f375b9456c887c5fdf047dc0ede499bbffd35637c35bc2c8c71c3903e7373ee2c6a707b4547ba1027d01b3f3d147a538f4758a5a68d90a5f973bd0eb58b8e5ceb81eff184cc95f9605f05c2c560cd0d355ac178754e740ddf48ec2f493f144431f3dcac841dff7c2f79a6c73fb53d2165ce57b526a179ac055395d7afe29650e15d6a409f7528939ba4a00e16880ab4ab6d1308a7144bd6d5555671e6f5591c780a1ecc741667f9f066d68421144cd27241a70ce64b28f0b08f036da569abc0847ae7f5e99b4a2c74d0d870d555312edc3cfa9f1781c9f5e4809073d201631bb773edc8aef19fc2e947c5952854194e3ea1d6c5ebe2206e3f989334bd1db3d346aa91521df6eed4be33f09d802fb10079de5216b65c3da5583eb2ee7bef38f84514f4eae2f51d2400a80c6d3ca85c04ce11070f9e909065ba8216c12f8f7ba0277a559cd8bdae289474a5bdffd51a93b6e124be70b1e1ad1d7ff72cb7fa2a7cedf0982c96c1d85ab50f111b03b62af8426e4556701230b3768e99780fe5ef9848c942427b079c0b389d5cf3873cdd14e974ba7c1896e6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151459);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id("CVE-2019-15271");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq95596");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq97028");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq97031");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191106-sbrv-cmd-x");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Cisco Small Business Routers RV016, RV042, RV042G, and RV082 Arbitrary Command Execution (cisco-sa-20191106-sbrv-cmd-x)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of certain Cisco Small Business RV Series Routers could allow an
authenticated, remote attacker to execute arbitrary commands with root privileges. The attacker must have either a
valid credential or an active session token. The vulnerability is due to lack of input validation of the HTTP payload.
An attacker could exploit this vulnerability by sending a malicious HTTP request to the web-based management interface
of the targeted device. A successful exploit could allow the attacker to execute commands with root privileges.

Please see the included Cisco BID(s) and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-sbrv-cmd-x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56939222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq95596");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq97028");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq97031");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq95596, CSCvq9702 or CSCvq97031");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(502);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
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

if (product_info.model !~ '^RV0(16|42G?|82)($|[^0-9])') # RV016, RV042 / RV042G, RV082
    audit(AUDIT_HOST_NOT, "an affected Cisco Small Business RV Series Router");

var vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '4.2.3.10' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq95596, CSCvq9702, CSCvq97031'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
