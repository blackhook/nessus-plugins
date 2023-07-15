#TRUSTED 81a5248bb21e9a0462fe42548d2d1d6dd28c21a161947ec60b9c983c8842296288e3602439a48f93195f84dd0baf33de7a9f9610e12fccd9ec31cf5b1935b29632a5e57b811e6a040af0357dae1a317e4af9ce469ae7a47b95b65bc868c54b9e9396e3cd8bb68402b0ed4b804992835ed7d081714204d8378ccbaf3fc44db8cfd871b9dd93efb653beea3a380319ed9875d51be40aa022a93f5688186eeb1e572257871aef925c234eef43b80b220bd469fda22f7aa73e39b79193e4c782b1fe32189c1fabb71837707cac8cf79638456304ce88ae26c8a8f8801559b96a0d04418d2b485eef428c8595b6137cacfb97a30137eb57d6fdb5fdf594b41c1b15d8de8f5d1afd4e2d5ef0b3c0ac6631cb2be8fdee9f4c95e67321f5de4fea6ad183edc9e77590e5589de51613a293440327ff2aff9d3a7e951e24e5cc9ebb7a0c87d09f0c9aa2c2e53709fe27aa69e7e579dfdce5e814d99aa13f2c0516a1d86e26e501142166964e6e7ba98cf1b0f30ad485ba4e07e5f39ed19c8762101c7f0264fdc06d8e21662cdc782cb875d8f987d84ded33f524e8af758145fc46c96fcd64b4c06966c4d44c72646d9cb215cff1ab68c50bd370e992d7cdfedb4f330057af5c8b7ff0daa00f714d0be5c1a03a13d193d2b89ca779ac67dc19bb65e6be94881b764a333e0bb7b608a0ace3dd780fb8e952281e826edff22e8907a88fd739ef
#TRUST-RSA-SHA256 5a4a8140a5201e6b7f7a5fbf17597e5db5888e839ca7e9bc305963e12c255942f2ed0b114de44f0493751418bc77dc02948c16f8d18e5a41fd2286af9d05031e7354b0a37fed6416ad8c0fce035436aa98ba93806e628825c5486aa1f313c8b6534ed9c49440801eb5726d07655d99155cdf7b8560f8506209b043a1b20c2d7627916432f8c288e51948b2b85371506495d3568aa0d1e66818d401c30faed8909209f705232d42211effa4d677b977b42ce264c7cc5d13727d8d8498f938eaa05d5f0704191790bab10800a5ebe5bdac2c971bf3fc2571b77affb0537bfc7d2381946e3ad269283cbfa8dbd714c74f4f67b1a07c4354ebcf0a52efee57655483b0617d21c14823871c9d6991793dd187fe052a8d8e356e9859e19ef34f193df34d2c1f94123728b26239adb5d7dbcb240eb1c84ee3f3296cbb4542275b65f37763a6dcac048790eb524824573758dc2b30de85538e5d0cff1b044e99098c504c3e4e56b99046027d337c47180a50ec7b3509c80d5336a48c885763907df3c5a6a85002cf9a1b102f77d88993f51aecf3d124fc4969b76e9648b3f30aad7ad8aa4960ce1226fab5cae07dee593ff4e11ce072bc783d06301a45e45d51ee9e56d9d0d68c693a7f4a3205c56724a64645b3c660e292b0a6e56810513881ea226677583a72a00468d614f36dab012d21704065cb1798e280cee51941731c81ca30ca
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155024);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-34794");
  script_xref(name:"IAVA", value:"2021-A-0526-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv49739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw31710");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw51436");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-snmpaccess-M6yOweq3");

  script_name(english:"Cisco Adaptive Security Appliance Software SNMP Access Control (cisco-sa-asaftd-snmpaccess-M6yOweq3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability.

  - A vulnerability in the Simple Network Management Protocol version 3 (SNMPv3) access control functionality
    of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software
    could allow an unauthenticated, remote attacker to query SNMP data. This vulnerability is due to
    ineffective access control. An attacker could exploit this vulnerability by sending an SNMPv3 query to an
    affected device from a host that is not permitted by the SNMPv3 access control list. A successful exploit
    could allow the attacker to send an SNMP query to an affected device and retrieve information from the
    device. The attacker would need valid credentials to perform the SNMP query. (CVE-2021-34794)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-snmpaccess-M6yOweq3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?973fba99");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv49739");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw31710");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw51436");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv49739, CSCvw31710, CSCvw51436");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34794");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.14', 'fix_ver': '9.14.2.4'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.7'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['snmp3'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv49739, CSCvw31710, CSCvw51436',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
