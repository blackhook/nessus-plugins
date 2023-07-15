#TRUSTED 8034c84c8296fd28e2e9813ded9b0d4ba8f4e8059b93b0a9a5e8a1c940e267bb2522b778e70337726689768ed7f7c2eb8097c2942120daa11002c4951e03418eaa95d577d13385385c1c19c6a0da1bbb9d32861044b2d28a68cd15842919b8d200ad60aec8e5b141cc4ba81e59b393e5824f485d02518f216745583668a843b8e91bcc963344f686af9ce4ba6f0bd6531e4cc75e0d583f9290870f39e7a7357b551ff382c8b5d09ea552b83c09f5ba033aeea7c82c7c3d8155c56f6239b9960f6257e4a1b9cca10b7ad9a23661890b144d191f69263ea21c8fa22f3c052e5b7ff90970a089e6cc44a71be2b0d66d53fb3d466730cf2d5a0221f40a29dd0a5fbe363be6ed18d49139fa88efbb88d4c9b2c15d20a6b28c22c684920e53468ae4d48a65ddcf8fea8527aa7e3d7663dcf9be7725f0e4e4c0bb7c7355b7b3bf3a7653456d876d932e822e602f12261c49ad7dece9a4cb22fb9efc6230d9310a96eeeca75c4346a70ac08b4eafe7d51864b47db0ccd8883e33f6a88a47208a71582f01f06e6bc2cdfcb165a8037e71e00c2fb3cc98d34ef37e90c7b6674fa3f76546af055bcbf6c6a7ee1a1b85bae98ac7e25cfe8c55b3128934acd98cd0331d097468d189c8dd1e0aabfa4c18181b302356a4795010bd68a33472389bdb3ffb447ca5179b7e527fa817a297f24c5ebbad683c803659cb496fc492b72069a706d056aa
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137144);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk71355");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snmp-dos-USxSyTk5");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS Software Simple Network Management Protocol DoS (cisco-sa-snmp-dos-USxSyTk5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability in the Simple Network Management Protocol
(SNMP) subsystem due to insufficient input validation when the software processes specific SNMP object identifiers. An
authenticated, remote attacker can exploit this, by sending a crafted SNMP packet to an affected device, in order to
cause a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-USxSyTk5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?528a5571");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk71355");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk71355 or apply the workaround mentioned in the
vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(118);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS');

if ('catalyst' >!< tolower(product_info.model) || product_info.model !~ "45\d\d(^\d|$)")
  audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version_list=make_list(
  '15.3(3)JPJ',
  '15.2(4)E8',
  '15.2(4)E7',
  '15.2(4)E6',
  '15.2(4)E5a',
  '15.2(4)E5',
  '15.2(4)E4',
  '15.2(4)E3',
  '15.2(4)E2',
  '15.2(4)E1',
  '15.2(4)E',
  '15.2(3)E5',
  '15.2(3)E4',
  '15.2(3)E3',
  '15.2(3)E2',
  '15.2(3)E1',
  '15.2(3)E',
  '15.2(2b)E',
  '15.2(2)E9a',
  '15.2(2)E9',
  '15.2(2)E8',
  '15.2(2)E7b',
  '15.2(2)E7',
  '15.2(2)E6',
  '15.2(2)E5b',
  '15.2(2)E5a',
  '15.2(2)E5',
  '15.2(2)E4',
  '15.2(2)E3',
  '15.2(2)E2',
  '15.2(2)E10',
  '15.2(2)E1',
  '15.2(2)E',
  '15.2(1)E3',
  '15.2(1)E1',
  '15.2(1)E',
  '15.1(2)SG8',
  '15.1(2)SG7',
  '15.1(2)SG6',
  '15.1(2)SG5',
  '15.1(2)SG4',
  '15.1(2)SG3',
  '15.1(2)SG2',
  '15.1(2)SG1',
  '15.1(2)SG',
  '15.1(1)SG2',
  '15.1(1)SG1',
  '15.1(1)SG',
  '15.0(2)XO',
  '15.0(2)SG9',
  '15.0(2)SG8',
  '15.0(2)SG7',
  '15.0(2)SG6',
  '15.0(2)SG5',
  '15.0(2)SG4',
  '15.0(2)SG3',
  '15.0(2)SG2',
  '15.0(2)SG11',
  '15.0(2)SG10',
  '15.0(2)SG1',
  '15.0(2)SG',
  '15.0(2)EX8',
  '15.0(2)EX2',
  '15.0(1)XO1',
  '15.0(1)XO',
  '15.0(1)EY2',
  '15.0(1)EY',
  '12.2(54)WO',
  '12.2(54)SG1',
  '12.2(54)SG',
  '12.2(53)SG9',
  '12.2(53)SG8',
  '12.2(53)SG7',
  '12.2(53)SG6',
  '12.2(53)SG5',
  '12.2(53)SG4',
  '12.2(53)SG3',
  '12.2(53)SG2',
  '12.2(53)SG11',
  '12.2(53)SG10',
  '12.2(53)SG1',
  '12.2(52)SG'
);

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk71355',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
