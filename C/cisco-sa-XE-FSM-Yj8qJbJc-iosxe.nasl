#TRUSTED 5f736c47c4c1d66ec36f84e3701736d126c66a8817c962d09193d94b76c9839aac1bbb89603a57be12b62582da384b1bc71fbfe7bad5f7cef6db5551516208c722cff7ea03b234c48194b66c9cb656378711ddec487cbd89218a2dcaf668a32905955a507f7aa5a13e872145c0285247195f6b4be409c78a4c3488540fde29df2ec1aa90cd3ae8996ccc14dce26b936b75bc5e500aa07c3e0e2720bb3381f8d5ea13fa63730405020baeac84da5ff08fe6747202b9fd37d12fd579ec175ebebc2a521c31b1f1136a4076fc5e990f4588f87d67fe2860a2d1d61bde6da5fafb51ccc6f367de34629eb83fa1510cb0ce1707ac2421f33f14a66aa8b76f267384692f9787dad5480ff4e054cd5000067c57d98edb5ab6b0df2e3594cca0bdca3fdf0818b93f7b59b14d56cbd4c0b52b57d725e04f6373ced53d633af35320882cfd777b20e2e5d02067cf2fff4279c346aff4d572eb1025414d0053dc1e707ba95b3c06e6df3f2e99406fd93b1a6ebebd29b8a93bead575af817c7831f926401ed2d8dbc2f363da94c40e94972ef35bdaa6057f1078e08aa9ab6751def59f84d9ba70a5044ab71ecb9705cc964a6cf46101c6d13aa2ba35cbe79a311113bd89a7a73792eba242f096aa503fc8c7bc2c4f7f07949b81e61ffb05f0c5ab00b634a8b318a219f417105c0143c05486d24ae24b5841038e0b9741de0abaa29cdde8fea1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148216);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-1391");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu58308");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-FSM-Yj8qJbJc");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-XE-FSM-Yj8qJbJc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a software privilege escalation
vulnerability. The vulnerability is due to the presence of development testing and verification scripts that remained
on the device. An attacker could exploit this vulnerability by bypassing the consent token mechanism with the residual
scripts on the affected device. A successful exploit could allow the attacker to escalate from privilege level 15 to
root privilege.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-FSM-Yj8qJbJc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?916c25c7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu58308");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu58308");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(489);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Vulnerable model list, note regex is case insensitive
if (product_info['model'] !~ "IE[\s-]?3[2-4][0-9][0-9]-|IE[\s-]?34[0-9][0-9]H-|ESS[\s-]?33[0-9][0-9]-")
    audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info['model'] + ' model');

version_list=make_list(
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3aE',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2'
);

reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu58308',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
