#TRUSTED 3faf21c786a9b50ff107fc0a18e6425b62e4bcbc574b3fc5b50b8de9357d76a01f8f60f4c1a85bd4afd9b9feca591dd23a3206cebe3bb2202e5570a64a45d222962adf14cb5b51867652631631f1098a1554cd5dfb778aa9d67f6ff431216ba0d7d9e3a8d28133a15876fb306d4b6fe0b0b3e8ab45e60aaf63723664130dc9e9f7f0a5fd182808292ee2bffd27fb4ab70478126bd440fde6469b3870fe39f1799cf255f4ee6bf63ba885103a0e118613bdb458f7c0d9429362767ddc10af63b06d94ef413a38826e1379d3338f914f978b099648982d682957973c1cba1a6abf0ebed4d628319b0ef526152a634009557ee112f06a5862cd4431f8c6b723c04c9e42e12dbc0806edf94150f4515038c9051974643061f61c96e31a50c2877b766930aca89094cd130f9b01a9585bfe253e94747e864847635e2d6dd8393f1e89f65a77fc5ed9f594186b0cd2765c95a4cf117a636dce1f6e02afc5e007b7910877a46ce992c071afed43a89728066ca4c199436b0f57c5d786cfb3573937a391768dbc0e8e18d6b003e6027280648bfe67adb2761a9c0d5863389711ab3964fe25625de75f29ab3e9ba03a94469e3a8c7d8335937467428ebb0deb45774f1be3ff32d87115f91cd57cbee49b7adbf1fe25059057e42d3650f216af516a69828d2d873a375bbe4238375268d00421cd25f59b9b2113c8c6f2ccfe16770b1d551f
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161088);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-20753");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa64992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa64996");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa64998");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sbrv-rce-OYLQbL9u");
  script_xref(name:"IAVA", value:"2022-A-0191");

  script_name(english:"Cisco Small Business RV Series Routers RCE (cisco-sa-sbrv-rce-OYLQbL9u)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in web-based management interface of Cisco Small Business RV340 and RV345 Routers could allow an 
authenticated, remote attacker to execute arbitrary code on an affected device. This vulnerability is due to 
insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending malicious 
input to an affected device. A successful exploit could allow the attacker to execute remote code on the affected 
device. To exploit this vulnerability, an attacker would need to have valid Administrator credentials on the affected 
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sbrv-rce-OYLQbL9u
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd2793eb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa64992");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa64996");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa64998");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa64992, CSCwa64996, CSCwa64998");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(121);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

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

# RV340 Dual WAN Gigabit VPN Routers
# RV340W Dual WAN Gigabit Wireless-AC VPN Routers
# RV345 Dual WAN Gigabit VPN Routers
# RV345P Dual WAN Gigabit POE VPN Routers
if (product_info['model'] !~ "^RV34(0W?|5P?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');  

var vuln_ranges = [ { 'min_ver' : '0', 'fix_ver' : '1.0.03.27'} ];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa64992, CSCwa64996, CSCwa64998',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
