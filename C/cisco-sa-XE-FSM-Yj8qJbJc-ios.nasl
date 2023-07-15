#TRUSTED 1b005e88ebfd27b841c8d289f8303be28f963880661a4d9fa52ccf746f27ebffdc60aa830c8c87c9c321e1a7ce7d3dfac98aa989ddff1434c2fdf4f9a97053dcaa8b7188427ae2711d3bb460d150e133d136e2668fc3b3e894f224e60963d76ca19aba509fbe61063080c7a8053bfdc956f708297ce2911ba999e72a09a5ecd6fc50a3d6b7841142e462aad0e7e1551dc6d419a88e2f648e961de1d82c865e4acc8baf148281eebcc6270d5282010401a5d4b83bb8c3cc8a5a3269ddd6cfc515cfc16acbfbc4b06a589e7344e2933d5f5f2f30ca1bb92e834a0a895e6e52d499d07ae674eb1a0430a681a5144a4f5316618594a6b756bc8126ad01189d3e910e0078daa823c5a4e67ea191551e2b476d5da1ae4bc4a9bfbe607ddb72c3a56e22675f69ea310a474e306525922566718e8cbcabc705b787fe80693e72edf3c57afe30be63eff0b3a724e6b3fe0743f29dd9047e29fe4e8d40a821dd8095854f05d1655147ed54abe7e6889faca8ff5e21e364065f89529e7ecfb7faf00e6bc58113bf93655fda1742aa0f22748deb6a6b96bab2a66940ab3a978d660b568e4c7bec33e20bd45e8ed9eb97114bd7d2ee3f678582b33fb2e5913a320763610f271f8aa914178513187d34ebae1c83b9588d68a692f333e9de37b5a9e1015a5ce0b67dde88af1b5f189bdec4af50bf317ad0e7337ae45595f62fad6ae411c317cf7f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148217);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2021-1391");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu58308");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-FSM-Yj8qJbJc");

  script_name(english:"Cisco IOS Software Privilege Escalation (cisco-sa-XE-FSM-Yj8qJbJc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by a software privilege escalation
vulnerability. A vulnerability in the dragonite debugger of Cisco IOS XE Software could allow an authenticated, local
attacker to escalate from privilege level 15 to root privilege. The vulnerability is due to the presence of development
testing and verification scripts that remained on the device. An attacker could exploit this vulnerability by bypassing
the consent token mechanism with the residual scripts on the affected device.

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

# Vulnerable model list, note regex is case insensitive
if (product_info['model'] !~ "IE[\s-]?3[2-4][0-9][0-9]-|IE[\s-]?34[0-9][0-9]H-|ESS[\s-]?33[0-9][0-9]-")
    audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info['model'] + ' model');

version_list=make_list(
  '12.2(6)I1',
  '15.0(2)SE13a',
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.2(4)EA10',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EA',
  '15.2(5)EX',
  '15.2(5a)E',
  '15.2(5a)E1',
  '15.2(5b)E',
  '15.2(5c)E',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7)E2a',
  '15.2(7)E2b',
  '15.2(7)E3',
  '15.2(7)E3k',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.3(3)JF13'
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
