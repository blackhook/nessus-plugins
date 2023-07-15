#TRUSTED 09f80d01984afdad9b6665f0b948fe748af3c6f2560aab47868c138238d9f9e809c0208068e29dd501ca3e88f99ea41270641cd4f9d96720437bc933bde27cb2e06b873b1b88993b18b37f437d7864693285ba5bb36e175db32a0a2d4857a9cb9d328c41e36a7164af49c7b878b749d99ad37655648a51b01f44567a87b0f71cb05acd3894cfc2febaa143004d74a62ddd414cad95f82e3b13dc7e7c05c1f3d01f3a3a06defcd32ec800befdc8f4656de0e29d0c4cc71e0d3489a8d09de6c59660a4b5e7c66183a59b26dfeb8126f6c7859e56a4baf4a37e83b7a815e8bb3cf1fa160de4f932ddf2d111c4a1800074b629b5aa7e2413f88b25bd835b9c481e0007e89f2b8aa9b668340a187a13eb7d45264878e16d988be8ad77fb7ca295092ada130523a20c38de63895c5c0ac9a567974a43493eb1a28bb6224f5d293d8250dcccd426252b2a4fe4497b2869a96075158bf1c039a02fd81c93210d5f2487f664e94566367e168cff9c2eaeab218815f4d356bfa4e5ed0881a21450912758b312f9426ff4f2ffe0d1650f1441a552d8512116c305c8a2695c6c22754878743842de4873bae6b8e26713b649e711aff34eef00957b826d9bae010853fcc9e1b2263d0cbe0f0e69a56863f1156d5c6c378a6b23bb2e4c9302805768eeda239440359737542639ff8ff09ae443100dab780a2adba2166893747673e90b61742dff
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137654);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/28");

  script_cve_id("CVE-2020-3228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd71220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp96954");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt30182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sxp-68TEVzR");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"Cisco IOS, IOS XE, and NX-OS Software Security Group Tag Exchange Protocol Denial of Service Vulnerability (cisco-sa-sxp-68TEVzR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Security Group Tag Exchange Protocol (SXP) in Cisco IOS Software,
Cisco IOS XE Software, and Cisco NX-OS Software due to crafted SXP packets being mishandled. An unauthenticated, remote
attacker can exploit this issue, by sending specifically crafted SXP packets to the affected device, to cause the device
to reload, resulting in a DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sxp-68TEVzR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc568213");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd71220");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp96954");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt30182");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvd71220, CSCvp96954, CSCvt30182");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

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

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.9(3)M0a',
  '15.9(3)M',
  '15.8(3)M3',
  '15.8(3)M2',
  '15.8(3)M1a',
  '15.8(3)M1',
  '15.8(3)M0b',
  '15.8(3)M0a',
  '15.8(3)M',
  '15.7(3)M4b',
  '15.7(3)M4a',
  '15.7(3)M4',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M1',
  '15.7(3)M0a',
  '15.7(3)M',
  '15.6(3)M6a',
  '15.6(3)M6',
  '15.6(3)M5',
  '15.6(3)M4',
  '15.6(3)M3a',
  '15.6(3)M3',
  '15.6(3)M2a',
  '15.6(3)M2',
  '15.6(3)M1a',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M',
  '15.6(2)T3',
  '15.6(2)T2',
  '15.6(2)T1',
  '15.6(2)T0a',
  '15.6(2)T',
  '15.6(1)T3',
  '15.6(1)T2',
  '15.6(1)T1',
  '15.6(1)T0a',
  '15.6(1)T',
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
  '15.5(3)M1',
  '15.5(3)M',
  '15.5(2)XB',
  '15.5(2)T4',
  '15.5(2)T3',
  '15.5(2)T2',
  '15.5(2)T1',
  '15.5(2)T',
  '15.5(1)T4',
  '15.5(1)T3',
  '15.5(1)T2',
  '15.5(1)T1',
  '15.5(1)T',
  '15.5(1)SY3',
  '15.5(1)SY2',
  '15.5(1)SY1',
  '15.5(1)SY',
  '15.4(3)M9',
  '15.4(3)M8',
  '15.4(3)M7a',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M6',
  '15.4(3)M5',
  '15.4(3)M4',
  '15.4(3)M3',
  '15.4(3)M2',
  '15.4(3)M10',
  '15.4(3)M1',
  '15.4(3)M',
  '15.4(2)T4',
  '15.4(2)T3',
  '15.4(2)T2',
  '15.4(2)T1',
  '15.4(2)T',
  '15.4(1)T4',
  '15.4(1)T3',
  '15.4(1)T2',
  '15.4(1)T1',
  '15.4(1)T',
  '15.4(1)SY4',
  '15.4(1)SY3',
  '15.4(1)SY2',
  '15.4(1)SY1',
  '15.4(1)SY',
  '15.4(1)CG1',
  '15.3(3)XB12',
  '15.3(3)M9',
  '15.3(3)M8a',
  '15.3(3)M8',
  '15.3(3)M7',
  '15.3(3)M6',
  '15.3(3)M5',
  '15.3(3)M4',
  '15.3(3)M3',
  '15.3(3)M2',
  '15.3(3)M10',
  '15.3(3)M1',
  '15.3(3)M',
  '15.3(3)JPJ',
  '15.3(3)JPI',
  '15.3(3)JAA1',
  '15.3(2)T4',
  '15.3(2)T3',
  '15.3(2)T2',
  '15.3(2)T1',
  '15.3(2)T',
  '15.3(1)SY2',
  '15.3(1)SY1',
  '15.3(1)SY',
  '15.3(0)SY',
  '15.2(7)E0s',
  '15.2(7)E0b',
  '15.2(7)E0a',
  '15.2(7)E',
  '15.2(6)EB',
  '15.2(6)E4',
  '15.2(6)E3',
  '15.2(6)E2a',
  '15.2(6)E2',
  '15.2(6)E1s',
  '15.2(6)E1a',
  '15.2(6)E1',
  '15.2(6)E0c',
  '15.2(6)E0a',
  '15.2(6)E',
  '15.2(5b)E',
  '15.2(5a)E1',
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
  '15.2(2b)E',
  '15.2(2a)E2',
  '15.2(2a)E1',
  '15.2(2)SY3',
  '15.2(2)SY2',
  '15.2(2)SY1',
  '15.2(2)SY',
  '15.2(2)EB2',
  '15.2(2)EB1',
  '15.2(2)EB',
  '15.2(2)EA3',
  '15.2(2)EA2',
  '15.2(2)EA1',
  '15.2(2)EA',
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
  '15.2(1)EY',
  '15.2(1)E3',
  '15.2(1)E2',
  '15.2(1)E1',
  '15.2(1)E',
  '15.1(2)SY9',
  '15.1(2)SY8',
  '15.1(2)SY7',
  '15.1(2)SY6',
  '15.1(2)SY5',
  '15.1(2)SY4a',
  '15.1(2)SY4',
  '15.1(2)SY3',
  '15.1(2)SY2',
  '15.1(2)SY14',
  '15.1(2)SY13',
  '15.1(2)SY12',
  '15.1(2)SY11',
  '15.1(2)SY10',
  '15.1(2)SY1',
  '15.1(2)SY',
  '15.1(1)SY6',
  '15.1(1)SY5',
  '15.1(1)SY4',
  '15.1(1)SY3',
  '15.1(1)SY2',
  '15.1(1)SY1',
  '15.1(1)SY',
  '12.2(6)I1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['cts_sxp'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd71220, CSCvp96954, CSCvt30182'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
