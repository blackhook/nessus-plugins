#TRUSTED a963d05fe65d7bcc79851b1f897762eb7b10ed6b20b6aad3845fa2b3a40596c6c179c5175ce58b77f1b592ae96190acbb4e0d57bee5e66ec547da290cfcf94e359353fb6746528f7566d09d715f733a38a3e91944aaef7aa2c823f91807bbdc55ae1826e280b3ca86c58ded609cbb283d2aa055da7fefdbde69d09ba72eeaa89c6d885886a28773aa68184181017ed78db6b108422823e103515438a700308cbcb9124749a5d9ffc0bdf2e999c479a1fca4e8004738c16a36d8f06657cfb2cd0c298c9ac4e0037495708f7e7a87df342244f6cc0b3d21718181613ba18f0bf83bfcc11bf9cebfb23c88516d2c48d17dc45ccf5f06ede8b891bd3fa5fd3834756fe13eda8fa9a71bd8a559a4876e63bc45c6aa079caaf4531ef70271c18c7898447f767535e1562d0af4bd7e3b81225c4f53945910f5e92b708600302b60128d42d7d6550a10a138d49b7b7b4babae736d508084214ae6377515b99c30ea2d71c7c6932da0a04da1d262152f0e257026dc81b5f94c4046a49d2d292ccaaec650cb9458492b557b00f48dc4ab369586a12a498211316c21996b64652c18c804b7e5e8c01706f98eec4b1334224c55e6fe873af64ffbacdc9510bdf99e47927b15caa7d478962c1697cc56a245ad2b309e319839a9c2055c4c953241fd10a2d843affd5e35e8b32e9ba751a28435b5e80bafbf56aa045bdfec84eec6810e2d01e5f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138017);
  script_version("1.12");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects 4000, 2000 Series and Cisco Catalyst 3900
if ((model !~ '[42][0-9][0-9][0-9]') &&
  ('cat' >!< tolower(device_model) || model !~ '3900'))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.8.9E',
  '3.8.10E',
  '3.6.5bE',
  '3.3.2XO',
  '3.3.1XO',
  '3.3.0XO',
  '3.10.3E',
  '16.9.5f',
  '16.9.5',
  '16.9.4c',
  '16.9.4',
  '16.9.1d',
  '16.9.1',
  '16.6.8',
  '16.6.7a',
  '16.6.7',
  '16.3.9',
  '16.3.10',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1g',
  '16.10.1e',
  '16.10.1'
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
