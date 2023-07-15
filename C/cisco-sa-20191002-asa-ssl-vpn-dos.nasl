#TRUSTED 82e547175f98bba7572d20aabf11a4ad042e2702bb83fc003ac772e8480c3cf2d397ecea2e8b083326b4b29f90c537ff1867b086871fd840be05d9103d5869ab0ad9f515c75bc335a2657e29252c75f0df54d0321eb53ec0f91b526f4f18aa02d107f04d4739f374f44913b19cfb4a622c078fd29bc0e549bc54ccfa49895a2661eef4a0173c61fef75272c28fdea047dcf3835771820f8c8e14e6fd7ed6dd6d3eb9a187117f5cc4397cc018ab1873d11b280e9bc27f018e07d45827a349668956ebb2d24e79c91eae5b4ca11f70171423e52040b93e38c8b4d1673c3c9e044feb2a93bb39cd3d593735393f95a7b4f44890f4ad508e4444fbd069a2ac6130dd067b436d36731c50eb1fd1e61c2917edaa5756443a5c5b1e65be3a8ffac781806f90ffb649e299514bf5bd6d02c48ae5a4f73b3bc5590d31326577543323ed2c07f5095984f5c0b1084e6666ff75c508e87edeaf4736da0c4637e2aca42a0908fa49e28c300863a235443d4303759ab7ad2f5859f9c9399d2890003fa836a0897d0d9ab081fe3081414604be40eea5dafa7f017763bac69e63535f5a2f31d8a187fcd6e2c97b248a96dbc20a84b08b304359d13d503bcd2d400fc5c3f15ab191d058e38cfbdb406fb8dcbdf0dda0daaeb748f053cc7518526631879c338d9f9ada92fc275bb7d53ff1320a4d1c4c587a5133e92e164fae9522f7001612b38a1d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129815);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2019-12677");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux45179");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-ssl-vpn-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Adaptive Security Appliance Software SSL VPN Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Secure Sockets Layer (SSL) VPN feature of Cisco Adaptive Security
Appliance (ASA) Software due to incorrect handling of Base64-encoded strings. An unauthenticated, remote attacker can
exploit this issue, via opening many SSL VPN sessions to an affected device, to cause a denial of service (DoS)
condition that prevents the creation of new SSL/Transport Layer Security (TLS) connections to an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-ssl-vpn-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74ef3796");
  # http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72541
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61c47b6a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux45179");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCux45179");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12677");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(172);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/show_ver", "Host/Cisco/ASA/model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

asa_model = get_kb_item_or_exit('Host/Cisco/ASA/model');

if (asa_model !~ '^55(06|06W|06H|08|16|12|45|55|15|25)-X') audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '9.1',  'fix_ver' : '9.1.7.4'},
  {'min_ver' : '9.2',  'fix_ver' : '9.2.4.8'},
  {'min_ver' : '9.3',  'fix_ver' : '9.3.3.9'},
  {'min_ver' : '9.4',  'fix_ver' : '9.4.2.7'},
  {'min_ver' : '9.5',  'fix_ver' : '9.5.2.5'},
  {'min_ver' : '9.6',  'fix_ver' : '9.6.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCux45179',
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
