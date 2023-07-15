#TRUSTED 287512c2a5d33fec617012c757959b825b9a0bea9e58bef295ca3d40725fc14806824910f43637d8c4e70ac1c9ea9d8be62291d8caed3ea31f17a9e890a5e43a4085cd463f3502855e0185d8eda9f29343d2576c10780671de23bb1e32e38e1f0476a9bd45fd23dec50fcb940bc4cfb3ee8ff740f2deecea9f1bd7c543bde0ba1560563d201f59997c864e513bbe49f6c1026732089c4e3a788811ce497d5bee6bd8fc840cb38c4e81a4bb0bda34b6a7f235aaea3e4af96dba807663bc211aca847dfac9d0ddf3c6111667380be7d7c9e4e72daad4b89139a4ae6349b71c9086e1b7aa476c94688cad8e31e9a6961a6437f1d31cd4999243bf43f62bfea61fed87e342a04a1b1ebf2180029f796f1febaa8df7d55712a9417da9f7bdd7e772493ae85d5974eeea43b647637a8b8ab33fa925d90a130effc3fe710e7121013b2cae4b6d07cb114af1d6cae6a7429d53959a495ba52b0bbff581678751c4b850c2fbfd9352c92fda949625761d5fc31fa378a3c9a3d2abb65abcf88394f545412068605732107d908bba7aeea195675185ca7de9da0cf7622aee466cc8a1a97af1ddffb8afbc45ee2be74fdfabd900f598982832ea3229c1c2ebcfab1e85583a70cb4acedcaa75c0ec93eef8228d67defa86b2e8b216d7373f30df23dd73cdb0b311cb171e0b80bbf78fdc68c00b346c5ab2282dea0286dc88768eeed3360573a8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136768);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2019-1713");
  script_bugtraq_id(108132);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj34599");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-csrf");

  script_name(english:"Cisco Adaptive Security Appliance Software CSRF (cisco-sa-20190501-asa-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by a cross-site
request forgery (CSRF) attack in the web-based management interface due to insufficient CSRF protections. An
unauthenticated, remote attacker can exploit this, by persuading a user of the interface to follow a malicious link, to
allow the attacker allow the attacker to perform arbitrary actions with the privilege level of the affected user. If the
user has administrative privileges, the attacker could alter the configuration of, extract information from, or reload
an affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7ac0f7f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj34599");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj34599");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',   'fix_ver' : '9.4.4.34'},
  {'min_ver' : '9.5',   'fix_ver' : '9.6.4.25'},
  {'min_ver' : '9.7',   'fix_ver' : '9.8.4'},
  {'min_ver' : '9.9',   'fix_ver' : '9.9.2.50'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.17'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ASA_HTTP_Server'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj34599',
  'cmds'     , make_list('show running-config'),
  'xsrf'     , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
