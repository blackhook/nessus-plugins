#TRUSTED 32c6b2963905571941666c343749e0b62f0e1c1327d579e789ef770af7aac8f5535888d8887d63b1b604e40e030958c57e2e091664320c7cf13c2ab43d52ad4c438ca153fe7dab7a4ac5c9282c4f6e5b6ee003f6fab73c8b2c7bf2b5f430d296a4b14ea257350ad379ba53c5eb1656430338317894a043b12b5fc03411e8bf8cf277367c721fb72f071dce7c22e76161e2871891f85439e0733ec50c5080b7983118c85b679a3f1fabf10f665364bd469fd709398a3bd6223b4a6980a2e5b24185b244e0be7493b705a96c44a92940392855b4c94dbab4238a0c03e6f4362efbfdf0d5bf6824316fc1a64935f7672a422edc56c03f4d1426d14a31b5578ef1a4db92e9eb18e024c6a2884461c61304a511b58b660eb1f3c1c59d377b071e04bc0741ac3580db964db66961b10ec2ab760038680c26ce1c048c41bd07b261583ac1e24666f59deafa2f3f8adb4e3666bf16eb54bff43baccf304866ef411256d3fe8ef6f8d6703f053793071c55e85a7464cf839daa7b2286bd738aaf0d6048d47e93b3eefd1d0d2ec030e1dd296b99858d060ffca5982eb756c5d8a00fa6755aed3c27b382e67acf8dbe172c88fdc707981ba65d4b16e99f462a654e04eecdd8471e53e5d0cc024f0f648effebf41914ef3804826de9a2610c9d3d46111e6abc76a57c4028891ca6f9fde2cf8c7296c3e8bf965318c0907dcad9bfc85afd49d9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134230);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3166");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr09748");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-cli-file");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco Adaptive Security Appliance Software CLI Arbitrary File Read and Write Vulnerability (cisco-sa-20200226-fxos-cli-file)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Adaptive Security Appliance (ASA) Software is affected by an arbitrary
file read and write vulnerability in the CLI due to insufficient input validation. An authenticated, local attacker can
exploit this, via crafted arguments on a specific CLI command, to read and write arbitrary files on the remote host.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-cli-file
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0375756");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr09748");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr09748");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  product_info.model !~ "^10[0-9][0-9]($|[^0-9])" && # Firepower 1000
  product_info.model !~ "^21[0-9][0-9]($|[^0-9])"    # Firepower 2100
) audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.8',  'fix_ver' : '9.9.2.66'},
  {'min_ver' : '9.10',  'fix_ver' : '9.13.1.5'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr09748',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
