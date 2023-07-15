#TRUSTED 96cf277ec3f21169010b66dc2465f362d1abf88c09900d43ab4d5bf05f1c75b85ba60f6a4eb73dfab0ad71e629b9fc08e3d7a08dd695ffca674ed07a4ade8ff4a2e6ed1c82c37a531f846f31db5865e62d598409ef54be5f1325148748e6f374b71a372bd84a5884ee15e52cda4fd842f5855b039116e4474454d239723d08c0798c675c141f91e7f497292460ccf7aea3fa49c301af1f76e684c5f3a8ed8ac15a6030485d9c2ca50f1c4dccf5952c14da6586146b6b0f44f288298cde5c80d706af4bd67cd96aa2df019df22bac3aae75112d0fc719220b34533e013f981a0d7158fdf9f43a27d154fccd243bd110beee5cd86de3c280d92d3ca2f17ca5bf311fc66d260f708485a9ef583f845c4032ae89c3750911d27d08c235b2eacee15a0b5f94e9766883ee947b811b2397f03690328c57a8fc88e2f53b6e05a71914944840c468f305d562b8df2d50d413aeeb4399d950104ce709b8b08888ea0a441522f178c7264d6818f0e8d8f720419651090c798eb48a7777f833208ffe392069492f96b170d7da116b3df9b76aa424c5313336c942996072bead4fe380d53919c9b8bbc885480b4e779beedc01eb52d241abce9b2adacafb04cb1f5737778b96631d96b83a0064f83c4fc2844cb5b241d8244e895e19095200c55f439398c38be742d4ad14ff56a4977616b450bb9696853147bce3e725a70844b23a7f8094c6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133841);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2019-15256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo11077");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-ftd-ikev1-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Adaptive Security Appliance Software IKEv1 DoS (cisco-sa-20191002-asa-ftd-ikev1-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security Appliance (ASA) Software running on the remote
device is affected by a denial of service (DoS) vulnerability in the Internet Key Exchange version 1 (IKEv1) feature of
Cisco Adaptive Security Appliance (ASA) Software. The vulnerability is due to improper management of system memory when
handling IKEv1 traffic. An unauthenticated, remote attacker can exploit this, via malicious IKEv1 traffic, to cause a
reload of the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-ftd-ikev1-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2df7518b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo11077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed version referenced in the Cisco advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

if (
  product_info.model != 'v' &&                    # ASAv
  product_info.model !~ '^21[0-9][0-9]($|[^0-9])' # Firepower 2100 SSA
) audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.7',  'fix_ver' : '9.8.3.26'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.47'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.17'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['IKEv1_enabled'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo11077'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
