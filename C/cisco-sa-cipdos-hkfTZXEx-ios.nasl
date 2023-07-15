#TRUSTED 3083ea82939771228261853dc4dd27bd30a78182b84997ccceb66d6cd3a6b998ee83ad753cbf0f1e3ae89c4592ad272b26b1cdf493f497417b247de01353943124baebfacbfd9ec2b5574975fe35272edc150b72ab4a8e61930f1f06f46569e19756a67d0e4944e79021fa131505bef713b6e51c801c32df3d2f5b649094a852f4bf6d7c5c6876f15479734de556c41f7432408a6af308740f22864cab96c7bbefad39ce346e8f4fe41982c3a7ccd7cbe4367b26137317f2773864876e4448815622a9c24fa89567e0a9cf78bf5326192b5afc178e7639cdc9cf3e1164c23091463a5a4498f2e60fc0dabe14646b9ab26eb19a7e52a4ca74ab82f896439ec28b40fa8b0e2093e3c56ce515e055f933dae084aea1523e4562b72a4b02c1c783d2afb6ee72656be055e6127752f5f3605a7fae1a1c0a893fd10078dd20744597af42472dc98f9fb6f490d51b2f6767e5db05c2fb0ded60887a01f8bb086c6d6c73bcd46e67bb5c0d29e908ffe33e8a8e8e8d946480b3e331ed5f9634e62097dd12ba3e3737dd188ad28b20f22c5bb3b07f9c9f9fabedef139b5688876369049968fb105e23b520cb93d5baad882c81a6b24f23d5eecee4d004b0a7523598807ff1a800645f1d57bcb7cd3cb746eabdf48e8ce50db6175f969d22a0c92b1ab4a8a94569e90146bff4c1c3a5304fe7354b5e5240a60edee620cdac792ba2447b6157
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138016);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo17827");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp56319");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr47365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr67776");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cipdos-hkfTZXEx");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS and IOS XE Software Common Industrial Protocol Denial of Service (cisco-sa-cipdos-hkfTZXEx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a multiple vulnerabilities in the
implementation of the Common Industrial Protocol (CIP) feature of Cisco IOS Software and Cisco IOS XE Software could
allow an unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of service (DoS)
condition. The vulnerabilities are due to insufficient input processing of CIP traffic. An attacker could exploit these
vulnerabilities by sending crafted CIP traffic to be processed by an affected device. A successful exploit could allow
the attacker to cause the affected device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cipdos-hkfTZXEx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0c4bbf1");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo17827");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp56319");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr47365");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr67776");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo17827, CSCvp56319, CSCvr47365, CSCvr67776");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

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
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');
model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects 4000, 2000 Series and Cisco Catalyst 3900
if ((model !~ '[42][0-9][0-9][0-9]') &&
  ('catalyst' >!< tolower(device_model) || model !~ '3900'))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '15.3(3)JPJ',
  '15.3(3)JPI3',
  '15.3(3)JPI',
  '15.3(3)JPD',
  '15.3(3)JPC99',
  '15.3(3)JPC5',
  '15.3(3)JPC3',
  '15.3(3)JPC2',
  '15.3(3)JPC1',
  '15.3(3)JPC',
  '15.3(3)JPB1',
  '15.3(3)JPB',
  '15.3(3)JNP3',
  '15.3(3)JNP1',
  '15.3(3)JNP',
  '15.3(3)JND3',
  '15.3(3)JND2',
  '15.3(3)JND1',
  '15.3(3)JND',
  '15.3(3)JNC4',
  '15.3(3)JNC3',
  '15.3(3)JNC2',
  '15.3(3)JNC1',
  '15.3(3)JNC',
  '15.3(3)JNB6',
  '15.3(3)JNB5',
  '15.3(3)JNB4',
  '15.3(3)JNB3',
  '15.3(3)JNB2',
  '15.3(3)JNB1',
  '15.3(3)JNB',
  '15.3(3)JN9',
  '15.3(3)JN8',
  '15.3(3)JN7',
  '15.3(3)JN6',
  '15.3(3)JN4',
  '15.3(3)JN3',
  '15.3(3)JN2',
  '15.3(3)JN15',
  '15.3(3)JN14',
  '15.3(3)JN13',
  '15.3(3)JN11',
  '15.3(3)JN1',
  '15.3(3)JN',
  '15.3(3)JK99',
  '15.3(3)JK3',
  '15.3(3)JK2a',
  '15.3(3)JK1t',
  '15.3(3)JK1a',
  '15.3(3)JK',
  '15.3(3)JJ1',
  '15.3(3)JJ',
  '15.3(3)JI5',
  '15.3(3)JI4',
  '15.3(3)JI3',
  '15.3(3)JI1',
  '15.3(3)JH1',
  '15.3(3)JH',
  '15.3(3)JG1',
  '15.3(3)JG',
  '15.3(3)JF99',
  '15.3(3)JF9',
  '15.3(3)JF8',
  '15.3(3)JF7',
  '15.3(3)JF6',
  '15.3(3)JF5',
  '15.3(3)JF4',
  '15.3(3)JF2',
  '15.3(3)JF14',
  '15.3(3)JF13',
  '15.3(3)JF10',
  '15.3(3)JF1',
  '15.3(3)JF',
  '15.3(3)JE',
  '15.3(3)JD9',
  '15.3(3)JD8',
  '15.3(3)JD7',
  '15.3(3)JD6',
  '15.3(3)JD5',
  '15.3(3)JD4',
  '15.3(3)JD3',
  '15.3(3)JD2',
  '15.3(3)JD17',
  '15.3(3)JD16',
  '15.3(3)JD14',
  '15.3(3)JD13',
  '15.3(3)JD12',
  '15.3(3)JD11',
  '15.3(3)JD',
  '15.3(3)JC9',
  '15.3(3)JC8',
  '15.3(3)JC6',
  '15.3(3)JC5',
  '15.3(3)JC4',
  '15.3(3)JC3',
  '15.3(3)JC2',
  '15.3(3)JC14',
  '15.3(3)JC1',
  '15.3(3)JC',
  '15.3(3)JBB8',
  '15.3(3)JBB6a',
  '15.3(3)JBB6',
  '15.3(3)JBB5',
  '15.3(3)JBB4',
  '15.3(3)JBB2',
  '15.3(3)JBB1',
  '15.3(3)JBB',
  '15.3(3)JB',
  '15.3(3)JAX2',
  '15.3(3)JAX1',
  '15.3(3)JAX',
  '15.3(3)JAA1',
  '15.3(3)JAA',
  '15.3(3)JA8',
  '15.3(3)JA7',
  '15.3(3)JA6',
  '15.3(3)JA5',
  '15.3(3)JA4',
  '15.3(3)JA1n',
  '15.3(3)JA12',
  '15.3(3)JA11',
  '15.3(3)JA10',
  '15.3(3)JA1',
  '15.2(7b)E0b',
  '15.2(7a)E0b',
  '15.2(7)E0s',
  '15.2(7)E0b',
  '15.2(7)E',
  '15.2(6)EB',
  '15.2(6)E3',
  '15.2(6)E2a',
  '15.2(6)E1s',
  '15.2(6)E1a',
  '15.2(6)E1',
  '15.2(6)E0c',
  '15.2(6)E0a',
  '15.2(6)E',
  '15.2(5a)E1',
  '15.2(5)EA',
  '15.2(5)E2c',
  '15.2(5)E2b',
  '15.2(5)E2',
  '15.2(5)E1',
  '15.2(5)E',
  '15.2(4)JAZ1',
  '15.2(4)JAZ',
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
  '15.2(3)EA',
  '15.2(3)E5',
  '15.2(3)E4',
  '15.2(3)E3',
  '15.2(3)E2',
  '15.2(3)E1',
  '15.2(2b)E',
  '15.2(2)EB2',
  '15.2(2)EB1',
  '15.2(2)EB',
  '15.2(2)EA3',
  '15.2(2)EA2',
  '15.2(2)EA1',
  '15.2(2)EA',
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
  '15.2(1)EY',
  '15.0(2)SG11a',
  '15.0(2)SE9',
  '15.0(2)SE8',
  '15.0(2)SE7',
  '15.0(2)SE6',
  '15.0(2)SE5',
  '15.0(2)SE4',
  '15.0(2)SE3',
  '15.0(2)SE2',
  '15.0(2)SE13a',
  '15.0(2)SE13',
  '15.0(2)SE12',
  '15.0(2)SE11',
  '15.0(2)SE10a',
  '15.0(2)SE10',
  '15.0(2)SE1',
  '15.0(2)SE',
  '15.0(2)EY3',
  '15.0(2)EY2',
  '15.0(2)EY1',
  '15.0(2)EY',
  '15.0(2)EX8',
  '15.0(2)EX2',
  '15.0(2)EK1',
  '15.0(2)EK',
  '15.0(1)EY2',
  '15.0(1)EY1',
  '15.0(1)EY',
  '12.2(60)EZ16',
  '12.2(58)SE2',
  '12.2(58)SE1',
  '12.2(58)SE',
  '12.2(55)SE9',
  '12.2(55)SE7',
  '12.2(55)SE6',
  '12.2(55)SE5',
  '12.2(55)SE4',
  '12.2(55)SE3',
  '12.2(55)SE13a',
  '12.2(55)SE13',
  '12.2(55)SE12',
  '12.2(55)SE11',
  '12.2(55)SE10',
  '12.2(55)SE',
  '12.2(52)SE1',
  '12.2(52)SE',
  '12.2(50)SE5',
  '12.2(50)SE4',
  '12.2(50)SE3',
  '12.2(50)SE2',
  '12.2(50)SE1',
  '12.2(50)SE',
  '12.2(46)SE2',
  '12.2(46)SE1',
  '12.2(44)EX1',
  '12.2(44)EX'
);

workarounds = make_list(CISCO_WORKAROUNDS['cip_enabled']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo17827, CSCvp56319, CSCvr47365, CSCvr67776',
  'cmds'     , make_list('show running-config', 'show cip status')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
