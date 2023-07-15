#TRUSTED 2e1aab1f2e9f28600e5d700e1ba6beed011d285a42e6e38fd0ef4e3645d359a08f6981568a8112d3efef62ccbe92abd8fa4301aa9d6b8ccf791fd778048c5a236263c55b694e16f44d97c40ee2e480be4d1cfcd3dc61fedc8b35e9e739f4e854d0832d1df81ae453b4d82b52bbe3b56adee6679388603bd2d8e6e6962d41da115cb76debade85f3e82dd5dd5cb040135b7409aa710c4ac7559d89249a16e55e16f2757bbb1b6c13ee51094224af5000c9dfe46676f90a8d3ec2274789153ef9064fd84d5c63379335395cdd94e6e4e6a049c8b5436cecc37d47c4d9514a38e71654a0c13e018bb95e6720668451fdc6c713ad3ffa530008ca5c03f94d0657dfffd557843e1b30a4cb7dd16a703a119598cf7b97dda3550c81be7296bfc601cb032fd733cfefa710253ac1120af0100403ad7847522bc9d5a74d243d1216200403564870cea64195facb1aaf10284aac878f313fba584339bb036c9d0ffd51dc326e02c1079301728636da1db9e5f19ffa882dd398d9c7957a7ef5b7af6da524d165171440d4acea5c2857836eca3f20b710db04e4ba14f95840bee911f1a9e5cb72e34cc62462363bdb9725f0d4cbe1615a01e603eb29beb9436900cbbd73be40fff6160f95f1de7434e1fcdcf7728e2fb9eacbc45d43b92f54d1c677ff264e51a329456cc42594172f934db8ba82c356b5a373942dc5e2516642d6353bab950
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137280);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3210");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq87451");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr18056");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-iot-vds-cmd-inj-VfJtqGhE");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS Software for Cisco Industrial Routers Virtual Device Server CLI Command Injection (cisco-sa-ios-iot-vds-cmd-inj-VfJtqGhE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability in the CLI parsers of Cisco IOS Software
for Cisco 809 and 829 Industrial Integrated Services Routers (Industrial ISRs) and Cisco 1000 Series Connected Grid
Routers (CGR1000) could allow an authenticated, local attacker to execute arbitrary shell commands on the Virtual
Device Server (VDS) of an affected device. The attacker must have valid user credentials at privilege level 15.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-iot-vds-cmd-inj-VfJtqGhE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d3738e3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq87451");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr18056");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq87451, CSCvr18056");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3210");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/10");

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

product_info = cisco::get_product_info(name:'Cisco IOS');

model = toupper(product_info.model);

# Vulnerable model list
if (( model !~ '^ISR(809|829)') &&
    ('CGR' >!< model || model !~ "1\d\d\d(^\d|$)"))
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '15.9(3)M0a',
  '15.9(3)M',
  '15.3(3)JPJ',
  '15.3(3)JAA1',
  '15.0(2)SG11a',
  '12.2(60)EZ16'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq87451, CSCvr18056',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list);