#TRUSTED 9e6055b777f31c7e304a848913d4f9a01e4f77414867eeb170ec6b9ad6190c3378cbdb4fb7a865b4df1f8de50372b71d6b574d4c2dcd4daeea70a39674e28a256b9706c036bf71d123efc137f1d79c0e53f81236dc6dc79fd3aaf2feb3b72d61896691fff780f4e5cdbfe9e828ec1546abadd0179efa184c513e6095054fa9e39cd7b709fa87048a40104a68b9320a555cd85613934be75bf2d95a897bdd639425fb8a895d3a727e7325fb769e123131c9566af441ecaebdff6a41aa2353435fc81e0f2b87c531c228a1c188a5a1db805197f54ecb610a6b047935567f8c79fcd8622ffe43cbb41867608d1939f1ea417b758a42abf24b431e13f3ad8b6791e6a58c741aaa85d307e2a8c347a4902f3dbd6a8e5c59eb7ed6094125280db4167cd3849252716b646d333e2ad300802b3925f7108c48124c3474ce770fdd00cb7815913942adc6d1cf94c78cece1684c982c92ea72c313a41893d424add613085057f11336eee23cb198f558bbc093274180ce9a7f75dd9462348f77702410cdfe86bfbb913975a211005ca27907673cb00e76d90eaf6b601db9df910ec21b3fda5fe5ea210dfdcc2a14578c4ec99a9e75d6e01e1613a44b233a7f0332b35af2834053e305fa8cf0e9542e29cf9b2ea4d2c6e79b788d970ab683659357d854656c57e48fd730047d0ab6b0b3a57f6a321f7be4b507c6ea8ab9e49f10ea3fc2beb6
#TRUST-RSA-SHA256 507def527592589ff25e8f950e03bb9e5a66eeda0fd1bc912d6728532aadd3b255c060fafc7b372e868d71d8e8b0505903eaa826613010326c27a9164b35b951358ad6bee29a8d44e7f9ece2efdc0f4abadee64e210592312784cd0edff10ed4b23295406a7dc07cdeeb5327c0d81e07df2e7732a62026442ad9f98fd5de56b7273dadb02cfe665fd78bb046dd262e8efc270fcccd5ab7b5679437b3d1a6a2c04d3542aa16545e873f08ec16f0a337e45070c37cc332b72bbc3d2fc2ea6ca35265727d19f2e37a12d4d2f3fbbf4147ab3cc4b9427848a199831b7d09c490509a8f0b7745dd2720fdb241aae4ad18bafc54f02f872c5524087713992f17521aef58182962ab50b914a31a48ecfbddb83ec8682dc83294eb55885acfe60d66e4c8a96d12ff66e368b41f8f21815379d242730f4f27b91a517fc03c431616e3b4d0f86d49d9b1bfda495f9b2aace942a0a8f0174e59ee22d8f4592f9b0fdfdbc57813bb2eb9273f38e6c94796694c5e918e8faf43af2c3e1879e16754481829b5dbfd55bfe0e67941817d0f8480aa31811aa3394d6d49123c40936f310e08721544a3f2a8739e4e7ee13b2ac55f7697e27b45c58166103a9bdbba0f2145869208682b6600adf7424142eda80ce2c53bc64c6bcefab35a748e2f9762136136e05b9f304ffeb7454d0fadb07c77e09aff4b718472ec9eaa2ee116293611c5590bcee7
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161262);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20760");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz76966");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-nJVAwOeq");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software DNS Inspection DoS (cisco-sa-asaftd-dos-nJVAwOeq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the DNS inspection handler of Cisco Adaptive Security Appliance (ASA) Software could allow an
unauthenticated, remote attacker to cause a denial of service condition (DoS) on an affected device. This vulnerability
is due to a lack of proper processing of incoming requests. An attacker could exploit this vulnerability by sending
crafted DNS requests at a high rate to an affected device. A successful exploit could allow the attacker to cause the
device to stop responding, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-nJVAwOeq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28fef957");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz76966");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz76966");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.44'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.38'},
  {'min_ver': '9.13', 'fix_ver': '9.14.4'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.21'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.14'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.7'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['dns_inspection'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz76966',
  'cmds'     , make_list('show running-config policy-map')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
