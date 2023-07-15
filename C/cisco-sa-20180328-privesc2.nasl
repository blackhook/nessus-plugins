#TRUSTED 6bf3dd43dfd10295de89a787e56276f1b75eefa4eb28237d52f64b58bb676304b4dcd30493e7ffef72d4e9720f92007658db3130f6a5c13067427ee4587fa716eaf018e6d5f3f8e360ce39510f12f1e0a7b4089c425cffab1e3d79128fa219b82610635ba4eba66d74409f7ceaf033a40ecaf6fd8266e316d19a0d7b260b57379d1c86e13dc5ca21f3ede8841d97bb83dcb1a249874c1393c13fa1cca89e44474b7e83fab37db1dfba4967529baa1d4947978ddb25db1fe2f78310773cb6c2096f363a8c84323e540636027f0be94d5d47327d3a59d5c01cf2e44f6f534e3ebcb6f3001a4c60a0f06bc1b7a89b6137857851cf32a766b8134d141a991f5e8b6624b7edb694d82c14f591e665781076f7a62253dc1e364a045d6fc939cb31000460f5194b21b4e676c95cbdd699b4ef2a2abb84a0437d9c46c8374992dec3bcbfc79eb29e409b352184845567c8a7d738dd8c6e3589438ba034ca5d66eb2aa3e37d3fd15422851e2718a2cec33b04c2cfccb559630e9368685c9462f46bf0a2ea16a550a20cf2589d1f7845640c8e6466c0fe9751770928f60cf80d68359313f888a47636a51cea664e9c8100e17b6840791ee0a989a1a2ee5445456c86920e1e5087957b043f9a530bf6b9ca63a13600361dd40a1a3074cd005cedc93bb4ab5924cbedecf02677da22467a8ebf8fd4f0868184543ea86d1a8165c9f71cb86528
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125031);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0184");
  script_bugtraq_id(103550);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve74432");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-privesc2");

  script_name(english:"Cisco IOS XE Software Privileged EXEC Mode Root Shell Access Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the CLI parser of Cisco
IOS XE Software could allow an authenticated, local attacker to gain access to the underlying Linux shell of an affected
device and execute arbitrary commands with root privileges on the device.The vulnerability is due to the affected
software improperly sanitizing command arguments to prevent access to internal data structures on a device. An attacker
who has privileged EXEC mode (privilege level 15) access to an affected device could exploit this vulnerability on the
device by executing CLI commands that contain crafted arguments. A successful exploit could allow the attacker to gain
access to the underlying Linux shell of the affected device and execute arbitrary commands with root privileges on the
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-privesc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c20c10af");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve74432");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCve74432");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0184");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [
  {'min_ver':'3.8.0E',  'fix_ver':'3.8.6E'},
  {'min_ver':'3.13.0S', 'fix_ver':'3.13.9S'},
  {'min_ver':'3.16.0S', 'fix_ver':'3.16.7S'},
  {'min_ver':'16.3.0',  'fix_ver':'16.3.6'},
  {'min_ver':'16.6.0',  'fix_ver':'16.6.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCve74432'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
