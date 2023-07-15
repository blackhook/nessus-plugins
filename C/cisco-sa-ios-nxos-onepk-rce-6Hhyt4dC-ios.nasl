#TRUSTED 8510896f68466deaa2464348f830ef17f6ad1eb79bacdf8056dba8c99c10f11a560ab6e3e0d60580866dfd4f108024a8fea6b7e60e0af62f15dca1c773ac8579c8db5c82f954325ac96d6658a1418ed3d8346cd7338e8c08f4781f37a3dfe97a0e2b3f55b966c89e5b77e3d8420175dcdf5244e4b30693e6f1cd7f4532475f5f9f070d13050fb0b629b8a0075bccd4412410f556cee791ca61ae771c7e0615b047931ad300a750d7a7cd2cd1b94b5587432c514d72f3a4362ae98aad9ea8457573a92416f490c7dc1e9f7758d53a38cf81d9af3993929f7c2bcfaf942a41fefe845e160638451a97e115a5cf953dea1fbb1aafa4452e18ce0b8ac01dec05bed748c15c087eebf39b40ecfdc3d33867209a6fa771ff3dbe142bd7e8f9375beeebdc435d287ddb4f00c10316f7ab2806e8632128302b65de40583dae8f921f93504591bf47f69c511289ecc0ccebf110960fa62acbcd31be3f19be0c22e0c05d2e273dd10d29f7f1cc17fa33d08afda379f81552ae1b18a8834465920c6f9f5284bb79fdc85ea26f71e5c64ff3c5ef5584ebfc9f717761c40b3ea21ab3d1fe71bccb19e2ab823cbc4df33d312b91e04f8e0aa48c1413e57f05f6691869e3c4c986ea65e3ee93e60bd00d28dbe8bff3e0953b64e3b130760602edf2d708329db597aef59ac947df062eeba3e3b9d8cb3cc9c51378bf3fb385daa61efb91ece7513f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137901);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3217");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh10810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr80243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs81070");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"Cisco IOS Software One Platform Kit Remote Code Execution Vulnerability (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a remote code execution vulnerability.
Therefore there exists in Cisco One Platform Kit due to a vulnerability in the Topology Discovery Service.
An unauthenticated, adjacent attacker can exploit this to bypass authentication and execute arbitrary 
commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38e0a857");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh10810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr80243");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs81070");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176,
CSCvs81070");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.9(3)M0a',
  '15.9(3)M',
  '15.8(3)M3b',
  '15.8(3)M3a',
  '15.8(3)M3',
  '15.8(3)M2a',
  '15.8(3)M2',
  '15.8(3)M1a',
  '15.8(3)M1',
  '15.8(3)M0b',
  '15.8(3)M0a',
  '15.8(3)M',
  '15.7(3)M5',
  '15.7(3)M4b',
  '15.7(3)M4a',
  '15.7(3)M4',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M1',
  '15.7(3)M0a',
  '15.7(3)M',
  '15.6(7)SN2',
  '15.6(7)SN1',
  '15.6(7)SN',
  '15.6(6)SN',
  '15.6(5)SN',
  '15.6(4)SN',
  '15.6(3)SN',
  '15.6(3)M7',
  '15.6(3)M6b',
  '15.6(3)M6a',
  '15.6(3)M6',
  '15.6(3)M5',
  '15.6(3)M4',
  '15.6(3)M3a',
  '15.6(3)M3',
  '15.6(3)M2a',
  '15.6(3)M2',
  '15.6(3)M1b',
  '15.6(3)M1a',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M',
  '15.6(2)T3',
  '15.6(2)T2',
  '15.6(2)T1',
  '15.6(2)T0a',
  '15.6(2)T',
  '15.6(2)SP7',
  '15.6(2)SP6',
  '15.6(2)SP5',
  '15.6(2)SP4',
  '15.6(2)SP3',
  '15.6(2)SP2',
  '15.6(2)SP1',
  '15.6(2)SP',
  '15.6(2)SN',
  '15.6(2)S4',
  '15.6(2)S3',
  '15.6(2)S2',
  '15.6(2)S1',
  '15.6(2)S',
  '15.6(1)T3',
  '15.6(1)T2',
  '15.6(1)T1',
  '15.6(1)T0a',
  '15.6(1)T',
  '15.6(1)SN3',
  '15.6(1)SN2',
  '15.6(1)SN1',
  '15.6(1)SN',
  '15.6(1)S4',
  '15.6(1)S3',
  '15.6(1)S2',
  '15.6(1)S1',
  '15.6(1)S',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.5(3)S9a',
  '15.5(3)S9',
  '15.5(3)S8',
  '15.5(3)S7',
  '15.5(3)S6b',
  '15.5(3)S6a',
  '15.5(3)S6',
  '15.5(3)S5',
  '15.5(3)S4',
  '15.5(3)S3',
  '15.5(3)S2',
  '15.5(3)S1a',
  '15.5(3)S10',
  '15.5(3)S1',
  '15.5(3)S0a',
  '15.5(3)S',
  '15.5(3)M9',
  '15.5(3)M8',
  '15.5(3)M7',
  '15.5(3)M6a',
  '15.5(3)M6',
  '15.5(3)M5',
  '15.5(3)M4c',
  '15.5(3)M4b',
  '15.5(3)M4a',
  '15.5(3)M4',
  '15.5(3)M3',
  '15.5(3)M2a',
  '15.5(3)M2',
  '15.5(3)M10',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M',
  '15.5(2)T4',
  '15.5(2)T3',
  '15.5(2)T2',
  '15.5(2)T1',
  '15.5(2)T',
  '15.5(2)SN',
  '15.5(2)S4',
  '15.5(2)S3',
  '15.5(2)S2',
  '15.5(2)S1',
  '15.5(2)S',
  '15.5(1)T4',
  '15.5(1)T3',
  '15.5(1)SY4',
  '15.5(1)SY3',
  '15.5(1)SY2',
  '15.5(1)SY1',
  '15.5(1)SY',
  '15.5(1)SN1',
  '15.5(1)SN',
  '15.5(1)S4',
  '15.5(1)S3',
  '15.5(1)S2',
  '15.5(1)S1',
  '15.5(1)S',
  '15.4(3)SN1a',
  '15.4(3)SN1',
  '15.4(3)S9',
  '15.4(3)S8',
  '15.4(3)S7',
  '15.4(3)S6a',
  '15.4(3)S6',
  '15.4(3)S5',
  '15.4(3)S4',
  '15.4(3)S3',
  '15.4(3)S2',
  '15.4(3)S10',
  '15.4(3)S1',
  '15.4(3)S0f',
  '15.4(3)S0e',
  '15.4(3)S0d',
  '15.4(3)S',
  '15.4(3)M9',
  '15.4(3)M8',
  '15.4(3)M7a',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M6',
  '15.4(3)M5',
  '15.4(3)M4',
  '15.4(3)M10',
  '15.4(2)T4',
  '15.4(2)SN1',
  '15.4(2)SN',
  '15.4(2)S4',
  '15.4(2)S3',
  '15.4(2)S2',
  '15.4(2)S1',
  '15.4(2)S',
  '15.4(1)SY4',
  '15.4(1)SY3',
  '15.4(1)SY2',
  '15.4(1)SY1',
  '15.4(1)SY',
  '15.3(3)JPJ',
  '15.3(3)JAA1',
  '15.3(1)SY2',
  '15.3(1)SY1',
  '15.3(1)SY',
  '15.3(0)SY',
  '15.2(7a)E0b',
  '15.2(7)E0s',
  '15.2(7)E0b',
  '15.2(7)E0a',
  '15.2(7)E',
  '15.2(6)EB',
  '15.2(6)E3',
  '15.2(6)E2b',
  '15.2(6)E2a',
  '15.2(6)E2',
  '15.2(6)E1s',
  '15.2(6)E1a',
  '15.2(6)E1',
  '15.2(6)E0c',
  '15.2(6)E0a',
  '15.2(6)E',
  '15.2(5c)E',
  '15.2(5b)E',
  '15.2(5a)E1',
  '15.2(5a)E',
  '15.2(5)EX',
  '15.2(5)EA',
  '15.2(5)E2c',
  '15.2(5)E2b',
  '15.2(5)E2',
  '15.2(5)E1',
  '15.2(5)E',
  '15.2(4s)E1',
  '15.2(4q)E1',
  '15.2(4p)E1',
  '15.2(4o)E3',
  '15.2(4o)E2',
  '15.2(4n)E2',
  '15.2(4m)E3',
  '15.2(4m)E2',
  '15.2(4m)E1',
  '15.2(4)EC2',
  '15.2(4)EC1',
  '15.2(4)EA9',
  '15.2(4)EA8',
  '15.2(4)EA7',
  '15.2(4)EA6',
  '15.2(4)EA5',
  '15.2(4)EA4',
  '15.2(4)EA3',
  '15.2(4)EA2',
  '15.2(4)EA1',
  '15.2(4)EA',
  '15.2(4)E9',
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
  '15.2(3m)E8',
  '15.2(3m)E7',
  '15.2(3m)E2',
  '15.2(3a)E',
  '15.2(3)EA',
  '15.2(3)E5',
  '15.2(3)E4',
  '15.2(3)E3',
  '15.2(3)E2',
  '15.2(3)E1',
  '15.2(3)E',
  '15.2(2)SY3',
  '15.2(2)SY2',
  '15.2(2)SY1',
  '15.2(2)SY',
  '15.2(1)SY8',
  '15.2(1)SY7',
  '15.2(1)SY6',
  '15.2(1)SY5',
  '15.2(1)SY4',
  '15.2(1)SY3',
  '15.2(1)SY2',
  '15.2(1)SY1a',
  '15.2(1)SY1',
  '15.2(1)SY0a',
  '15.2(1)SY',
  '15.1(3)SVR1',
  '15.0(2)SG11a',
  '12.4(25e)JAO7',
  '12.2(6)I1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['onep_status'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176, CSCvs81070'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
