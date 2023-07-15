#TRUSTED a7ec0ccbf98989445ef326f7857ed412d3a1dbe3e751572c2b4190d6a2ad3f70cb22f32f4166b611a9505dfd05184e989ccc231c604131ba68305ec8a32b152aa9dff18cc9f3674a4d67cd7d92423fbeac0cd82a12b355799ac36ba9dc3c7b16f7710547694adaf0d1f47f64b80502220dfa7b50bde85e52ba698667a087300aba2225f6e699fee709429c0a7c4e47c9478eaf7fc9db3285bf4f8237bbd7eff6dfb795bb611f7541398136776b4a3bfe1909353e49ca268fd3b29f720ae7412cd29257f1966c155f013c517a5574a32d341707d0aaef4c5fccb1a443562069e3cf402da9b4f2b55ebe4a673e5d3713fd69d7d98af28ce9aebcd4aa57d5e6d67c49aa5d947464ce7cec6fb3b6f946aa14c30f59594cfd331607ee09665386637dc1cd38dca5ef57132b75f5496a335d8de49a147e14fd3f9b4d3d9bfc81dfd2cc4dd9551dc3dd55915c433561dcebf2d2ec4b2ede4de5671bf7b6c78239be793b575d2320bb3246621d4fc8e959bd48739527e8c1f6235a58d2d7ba4f68be8cdc1bc28918fbc54892ca6d36f05f443af286645b9843a1a40e3064fc17186dc78d07616a711e80d88b75adab332433308621fa3f463d31fe9e9daa301244546f9b526c7aa9a293d8b2e328ae2e541af5f71455b786c2593c269eb5cccb319a52b867cf2a11d56d06cd61c2dea83bcb91064f42ddd34a8dd508cb53270736823966
#TRUST-RSA-SHA256 74ee71902e94b30207cf4be929a5825b7516978dffb4619585c0919927370d173a34b88743171cf8f91b643029f7ebb61f10c724aa584a64663a74ea9dd37b5e47314978390aaa1d95fd915bc66ce69618e62d1b22812e259db1dd6b8e4126585c77d5a30503ff621f7dcce748dcf702c09c80dc81b8b7346bf691fa2a1146557ca00e02905ad35ada0383b5413f8049e9d927943de333b1a8cf3976032fd68ef738f3da459facf279aca58293161b1fe658c4d5484c0b5352a9c1c69f57bf4f10a464b2973790421f3db41f00680caa3980183f4eea71811d8617fc40477cd73c8845be02e86a0524dfba06ae71c0657e0d17f0f43d04f115ce55ad5a16cde14f7403e6666baabdbf50117d7ebd2cc3f4cb6e4890f397eabe7a662b9513c00f9f991b26084788065bc9c85d5b055a1ff48a3f5f1fef3c8093024c1d5676a5a48b5b15e1ca328e5050beb824893225b089628a7c691072f5656aa03fb36383ea37da495bf44964fb1dde1b59fad621df1504864fc7efbeb6bef8e1824ff42413baf2b5deb2861fa9ec2053cf405bdbda02173f0bd296876ed8baac5b8232faf9fc78a330346df03b834173163f05466428090a89a71bb55ec31811bbcc8696e41645fd8440b589ee78a5b0523766ca2b10174791a08cae49164552f0d1aac9e9d399093b4e94b786487e96766645dfc22e689f29f0ecbd759707095408910d93
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136916);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3196");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49481");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp93468");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ssl-vpn-dos-qY7BHpjN");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Adaptive Security Appliance Software SSL/TLS DoS (cisco-sa-asa-ssl-vpn-dos-qY7BHpjN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the Secure Sockets Layer (SSL)/Transport Layer Security (TLS) handler of Cisco Adaptive
Security Appliance (ASA) Software due to improper resource management for inbound SSL/TLS connections. An
unauthenticated, remote attacker can exploit this, by establishing multiple SSL/TLS connections with specific conditions
to the affected device, in order to exhaust memory resources on the affected device, leading to a denial of service
(DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssl-vpn-dos-qY7BHpjN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6420bb6e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49481");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp93468");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '9.6.4.40'},
  {'min_ver' : '9.7',  'fix_ver': '9.8.4.20'},
  {'min_ver' : '9.9',  'fix_ver': '9.9.2.66'},
  {'min_ver' : '9.10',  'fix_ver': '9.10.1.37'},
  {'min_ver' : '9.11',  'fix_ver': '9.12.3.2'},
  {'min_ver' : '9.13',  'fix_ver': '9.13.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp49481, CSCvp93468',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
