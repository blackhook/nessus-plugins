#TRUSTED 29e5e75649eed028044f2584a17fda32e40735561493acbdf40f715ba1bdb47a8a5d8771e9f0cf753162cb12f3e816d4260e78ec218f490e109e305bab0519cb0cb2b17401dde4a4fb9fc4d3bc79b228fd661871cda7f0963493406aeb1bd2a4aa3de206900ee6776da45026384f605eb915bb84bc914c68aff052dfbf48227e2d4ca058a11bb3e13bed3b336ba2c44e9650696ae274e7a049858b9cfa742c64364c245f8eb4f4b1c9484d1f5e6bc417fd011cb9f4a74131bbafcfceef09ec966a91d44a55c79bd441dafc4875fbc3696f9760c867b0439ea9e6426e48d7ca3a74494db4634bc1dccdb454cce6d7c6a1a5bdbcf744c36a7ba08c989fae3fe5f373b48819f8378471af5f3af18ef60ecb739e13892f8ff2ca1ca888476e2535fdca0e0fba897bfb6c70586726dc58057287fd388667cd775c302e3e11da4f75f850d5e42381b8517f94fa31b95d09b950733054d7d4ea24582079c051609485e60113d3d0b7601c947de041fdf9bbd5d74682fabfcf7d200d026fb885fe303d00a692f07fcd8e3347bdabd523c1590f4f35510a880e2914ab56b4ea91c1d3c5827f67e424a8bf42e2d5cf25f47835f9c79faa2c1ed118d999639fcc8dcb73b3bee025e55e1ba5b9bf01ea4f35e79c05f7cdb5e017d783b4171f61a247c79de163940dacb4368d06175b37e06a3f3c8f4940c912cf7f7ae5d9c6ce8e2be1135545
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153209);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2021-34721", "CVE-2021-34722");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48001");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48002");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-cmd-inj-wbZKvPxc");

  script_name(english:"Cisco IOS XR Software Command Injection (cisco-sa-iosxr-cmd-inj-wbZKvPxc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by multiple command injection vulnerabilities that
allow an authenticated, local attacker to gain access to the underlying root shell of an affected device and execute
arbitrary commands with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-cmd-inj-wbZKvPxc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00664814");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48001");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx48001, CSCvx48002");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78, 88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
 {'min_ver': '0.0.0', 'fix_ver': '7.3.2'}
];

var workarounds, workaround_params, cmds;
# Workaround check needed for versions < 7.1.1 to show CVE-2021-34721
if (ver_compare(ver:product_info['version'], fix:'7.1.1', strict:FALSE) < 0)
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['xml_agent'];
  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx48001, CSCvx48002',
  'version'  , product_info['version']
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
