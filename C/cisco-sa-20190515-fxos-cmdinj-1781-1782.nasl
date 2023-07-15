#TRUSTED 6f68092e27c4e4d2f1702fdaa7e2744f5ce181387704d33139d448ff7867f26cb5e708d9ebe97e4e631549a21b1d910fbf9bfa2c0c0a4acb6c76ad02e2b7309f5c3851efa47efeddf1fe0401737f71876843044b4b446a5fe19be1211f871c9b98286857b9915f6afa622b0d2eebbb6d21c332c0198dedac2c9aca7674b740e38123663aec47c9294011ce380c6ec7b737032ac32f603e6bd248c4347f44b1fee3c841f0adc6b2edd0054566ac8e7daa229f6147fa89999d11711e89b3323b8050ac5996a42d9de18330edfe395bbaa872a7e81da4b9f19067ec798fa74d5a79924019e60b6786902beb5ddba557a6d8ef1a988da5e20ae5fdb589749c53692cbee3322c890495ebc0545d40fe8fea66cd76871983b129ba71fa8e2110d000b70e3d7246ca7bb859c0ddfd58461b6467ec0955e1349c6e45921170cdcf5d5b032e610d2627186d34ecebfa55170d535250a44077a1a8d218ab6c095f5d046e57e334d815c17d105a6ffe049b1d084e08c0b4ef1fac356c74aa3de885aff8b137d8a884b4c40acfa4872458cb7275fbc6a7923477c824192987134eca28f81c6e72066dfd417587cb231e21c4cff002d785f47ddae4135da710ecd7c961581ab920964121c8530e762839e0734da8cbbcc5b916dc27d1795c4aaf33721b905d0ff19efae12e807559ab93e35b056d188ed9a6753a6351b8d13d7fc14c91685d24
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129945);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2019-1781", "CVE-2019-1782");
  script_bugtraq_id(108407);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96527");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92130");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco FXOS Software Command Injection Vulnerabilities (cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782)");
  script_summary(english:"Checks the version of Cisco FXOS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by vulnerabilities 
in the CLI that could allow an authenticated, local attacker to execute arbitrary commands on the
underlying operating system of an affected device. This vulnerability is due to insufficient
validation of arguments passed to certain CLI commands. An attacker could exploit this vulnerability
by including malicious input as the argument of an affected command. A successful exploit could allow
the attacker to execute arbitrary commands on the underlying operating system with elevated privileges.
An attacker would need administrator credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d66d198");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96527");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92130");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi96527, CSCvi92130");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1781");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2.2.91'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.130'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.222'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi96527, CSCvi92130'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
