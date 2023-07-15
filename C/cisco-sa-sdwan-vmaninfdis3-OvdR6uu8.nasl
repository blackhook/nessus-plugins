#TRUSTED 93e4bafb9063f15d01a93c2583a1bf2d50112750e66712e871758462a1119266f419526516b4873fedb4b9950519fddeefd848f1991900806150b44564e254c1955fca7d519316767c8f8084ce8718576b330ce284010a8accc1abf3f0cbb6e4bdc510cf02e597256f9a972d6288287f577ed32896e8314164f674cfab700813e5db9b0fc81c3996d714352db409043c190031ccadb55fc7f33a9aec5d734b37694ebf8e95eefa11cc8f4a77050b5bb4e21b0bf871c8437efed69424e4e623bb1fb999f6ff77af837fa204bd6457bf2a50448b0879c200c074ae590b84e07f0eca1e8a0d53a12e9414b6fd3b42e944bf86e19b9d08b2be6b5fce18455b981c05f015b954c7fb043086ac73e8539e023e61b588776ff386289cf2c0c94118fde60707ea06f37fae8d25833843431d886b9f9a8230051610c8667e0bb7d6bd7a7d6b6fa16686be2db24a9a40918541ef0ee241c4e4260c5f8b7278691b2de80d916998e9f17476792cb07c9ea6247293a1a99195db70088f44e7a1ada7d603c82f96f5f48f1878e432611aaf179467f9f36dcba4f60a1963b433af010e425cbbe5e7bc1174480e7ee265a28a86b11cc1e907bf3a9ba58ff35b404c07f5663e0c2c07c3fc14fe0377dabbee415c6fc4eded742178455a0d19c8178cdf42516761c7fc1b83e84e2711c07c90789644819e92e2126c7f2ba486d659efb2819062bc15
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149362);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2021-1234");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28438");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28450");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vmaninfdis3-OvdR6uu8");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-sdwan-vmaninfdis3-OvdR6uu8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by an information disclosure
vulnerability in the cluster management interface. An unauthenticated, remote attacker can exploit this, by sending a
crafted request, in order to disclose information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vmaninfdis3-OvdR6uu8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4bf938e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28438");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28450");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu28438, CSCvu28450");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1234");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu28438, CSCvu28450',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);

