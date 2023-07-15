#TRUSTED 071ed711d3c54741c5151caaa57f037bec7baf7f348da13cc3c8108121cb1d614873230fd1e3337ea6693aac3bc11058294644e58f31b94275c9ab0bf72197cb2ea8b4f007044c865b989fa8caf77c927e3770356cf03211530c121b7b2984242ba901be3a933cb36c903193ca42f95d80ce6e1e6b13d04122f7a55a5aaf26e39bf875b614530556f012957b135d4064eff91ff1a95450a005c7c23c69fe0dd54f7aac8872cd0e7545f7f288a214bbd2a5e90edc0c641410b7a8931abd71650fecac15fa3749ce6a2ba71f5a1bd8409623ec6e8b43b9ac0dab778ff2abbae8e64dfb65d9954b25bee6eb9230596af8a58b11fa5a68ee6df662c0a23e4abcd02d5863f045d3b231df69ac3c2ad94f5ad46cf0993f8e16cfbe4b55d6d04edaa3873aa6c8dfb9db469ff6deb9c9a78218c60e61c6f69d4785a1ac082b946ebebd653f6f67b45ddea0f59ab4f7fd5d67b2c5abb078a89564a45f6ea68fbcd41192d50d024febfd71a6e80fbe82357761ca1c69a718b35fa9c08643965a6ea828778ab5f870e53df1d82c6d911665f644c1d84bbeb15affc73c74d43265722d027a146820722d6f0244c0cdee65b150b77eff1a4159693313946c0b24f5208f5fe9e0d62616ea9b1c5711b5c549d2c119368c02e3b9c8e8197bb1791d210197fe720f665e0a2eeca78f4d3650d53131542b23f46bcd246161cfc9d82a2d17c458d239
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134562);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12649");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj87117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk12460");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-digsig-bypass");

  script_name(english:"Cisco IOS XE Software Digital Signature Verification Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability that could result in the
loading of unsigned firmware on boot. An authenticated attacker could exploit this flaw to load malicious firmware
onto the device. (cisco-sa-20190925-iosxe-digsig-bypass)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-digsig-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb9bf05a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj87117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk12460");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj87117, CSCvk12460");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/local_checks_enabled");

  exit(0);
}
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];

if( 'catalyst' >!< tolower(model) || (model !~ '3850' && model !~ '9300')) audit(AUDIT_HOST_NOT, "affected");


version_list=make_list(
  '3.2.11aSG',
  '3.2.0JA',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1'
);
workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj87117, CSCvk12460'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
