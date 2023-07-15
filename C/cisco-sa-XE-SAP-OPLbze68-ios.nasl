#TRUSTED 05c69407b2ede566bf2e3f09d2cc58f3b5e412b9a2e1fca62a95e34c55f47e70750b45e37718fbad0a1a68fb925141ea7975026f7318a8070d80873c22e372b42a7dc6db892e12ba370f3b859eac411c74b172015fd882ad079a87c4261979cf89b550bcbe2b1b28f997b7a1b49a304893657a107d6c88cc3a68cf09a11e70c28bfa484506cb93a5995395a99b15565b3ecd8d9f8b464252cf93561d21939b75c3a1d2118ac576f7d493f677ca6448dac4de1b1b7934d607045d42164d318d1cd392a0e5babbace960dc767d143d412a9c2cbfe899c1c8f0bf5f9c8ff0d9baa0ba1f516837048ccdb72b1a695e4c148c6bb64f98635046874e0e7e43c5bfa6539e3c633ac7137a0dd9787d239c89f4ea72b27c46745bd40d71bf51c6bb4edb77d21f5a732925c77a50e80805d09eb4479441e6ce4036aabe1c1293eae9211a3e792f1ffb8be5511eabc16910923a861268b6d0533709c473af329c6b4d44b1a0c364d9bb16f081e7e21fb732ed6d9178cf8b800b921891227edaf26ec9570930eed77afbe7bd155082868142e4b86348337f2f0ecc88b97ced77afc64a1160e96a7f2af4d381a26b5c583f9bc68fe5940dd4553babb2c7d2b159add675b63b78d566866df1d1f1da5e8be77b0f426c57db94954465d4d48e6bc9afd91680a047f9dbe41a6705d04ea3dcb18c3667f180e2184dae8141581f64a9d275a3532662
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148221);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/13");

  script_cve_id("CVE-2021-1392");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu58224");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-SAP-OPLbze68");

  script_name(english:"Cisco IOS Software Common Industrial Protocol Privilege Escalation (cisco-sa-XE-SAP-OPLbze68)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the CLI command permissions of Cisco IOS Software could allow an authenticated, local attacker to
retrieve the password for Common Industrial Protocol (CIP) and then remotely configure the device as an administrative
user. This vulnerability exists because incorrect permissions are associated with the show cip security CLI command. An
attacker could exploit this vulnerability by issuing the command to retrieve the password for CIP on an affected device.
A successful exploit could allow the attacker to reconfigure the device

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-SAP-OPLbze68
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5e5f5d9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu58224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu58224");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(522);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.0(1)EY',
  '15.0(1)EY1',
  '15.0(1)EY2',
  '15.1(3)SVS',
  '15.1(3)SVT1',
  '15.2(1)EY',
  '15.2(2)E',
  '15.2(2)E1',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(2)E5a',
  '15.2(2)E5b',
  '15.2(2)E6',
  '15.2(2)E7',
  '15.2(2)E7b',
  '15.2(2)E8',
  '15.2(2)E9',
  '15.2(2)E10',
  '15.2(2)EA',
  '15.2(2)EA1',
  '15.2(2)EA2',
  '15.2(2)EA3',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.2(2a)E2',
  '15.2(2b)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(3)E4',
  '15.2(3)E5',
  '15.2(3)EA',
  '15.2(4)E5a',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(4)EA2',
  '15.2(4)EA3',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.2(4)EA7',
  '15.2(4)EA8',
  '15.2(4)EA9',
  '15.2(4)EA9a',
  '15.2(4)EA10',
  '15.2(4)EC1',
  '15.2(4)EC2',
  '15.2(4)JAZ',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EA',
  '15.2(5a)E1',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(7)E3a',
  '15.2(7)E0b',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.3(3)JA1',
  '15.3(3)JA4',
  '15.3(3)JA5',
  '15.3(3)JA6',
  '15.3(3)JA7',
  '15.3(3)JA8',
  '15.3(3)JA10',
  '15.3(3)JA11',
  '15.3(3)JA12',
  '15.3(3)JAA',
  '15.3(3)JAX',
  '15.3(3)JAX1',
  '15.3(3)JAX2',
  '15.3(3)JB',
  '15.3(3)JBB',
  '15.3(3)JBB1',
  '15.3(3)JBB2',
  '15.3(3)JBB4',
  '15.3(3)JBB5',
  '15.3(3)JBB6',
  '15.3(3)JBB6a',
  '15.3(3)JBB8',
  '15.3(3)JC',
  '15.3(3)JC1',
  '15.3(3)JC2',
  '15.3(3)JC3',
  '15.3(3)JC4',
  '15.3(3)JC5',
  '15.3(3)JC6',
  '15.3(3)JC8',
  '15.3(3)JC9',
  '15.3(3)JC14',
  '15.3(3)JD',
  '15.3(3)JD2',
  '15.3(3)JD3',
  '15.3(3)JD4',
  '15.3(3)JD5',
  '15.3(3)JD6',
  '15.3(3)JD7',
  '15.3(3)JD8',
  '15.3(3)JD9',
  '15.3(3)JD11',
  '15.3(3)JD12',
  '15.3(3)JD13',
  '15.3(3)JD14',
  '15.3(3)JD16',
  '15.3(3)JD17',
  '15.3(3)JE',
  '15.3(3)JF',
  '15.3(3)JF1',
  '15.3(3)JF2',
  '15.3(3)JF4',
  '15.3(3)JF5',
  '15.3(3)JF6',
  '15.3(3)JF7',
  '15.3(3)JF8',
  '15.3(3)JF9',
  '15.3(3)JF10',
  '15.3(3)JF11',
  '15.3(3)JF12',
  '15.3(3)JF12i',
  '15.3(3)JF13',
  '15.3(3)JG',
  '15.3(3)JG1',
  '15.3(3)JH',
  '15.3(3)JH1',
  '15.3(3)JI1',
  '15.3(3)JI3',
  '15.3(3)JI4',
  '15.3(3)JI5',
  '15.3(3)JI6',
  '15.3(3)JJ',
  '15.3(3)JJ1',
  '15.3(3)JK',
  '15.3(3)JK1',
  '15.3(3)JK1t',
  '15.3(3)JK2',
  '15.3(3)JK2a',
  '15.3(3)JK3',
  '15.3(3)JK4',
  '15.3(3)JN',
  '15.3(3)JN3',
  '15.3(3)JN4',
  '15.3(3)JN6',
  '15.3(3)JN7',
  '15.3(3)JN8',
  '15.3(3)JN9',
  '15.3(3)JN11',
  '15.3(3)JN13',
  '15.3(3)JN14',
  '15.3(3)JN15',
  '15.3(3)JNB',
  '15.3(3)JNB1',
  '15.3(3)JNB2',
  '15.3(3)JNB3',
  '15.3(3)JNB4',
  '15.3(3)JNB5',
  '15.3(3)JNB6',
  '15.3(3)JNC',
  '15.3(3)JNC1',
  '15.3(3)JNC2',
  '15.3(3)JNC3',
  '15.3(3)JNC4',
  '15.3(3)JND',
  '15.3(3)JND1',
  '15.3(3)JND2',
  '15.3(3)JND3',
  '15.3(3)JNP',
  '15.3(3)JNP1',
  '15.3(3)JNP3',
  '15.3(3)JPB',
  '15.3(3)JPB1',
  '15.3(3)JPC',
  '15.3(3)JPC1',
  '15.3(3)JPC2',
  '15.3(3)JPC3',
  '15.3(3)JPC5',
  '15.3(3)JPD'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['cip_enabled']
);

reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu58224',
  'cmds'     , make_list('show cip status', 'show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
