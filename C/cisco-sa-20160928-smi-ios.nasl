#TRUSTED 9a556b164441615dddf03d70de6de34374ee326502b2f95214de152128d387fde7a230c8b38cbdff8873f7d0f291a7a40e21a30f6716d0f849b2ac3d994391b85662880314a5d4c9b7dfce9d6c415d3dac2f536500748a2b649bef010f1c3ae2f56641baada40ff8ccb5da17ea44545672e0afe4478acfe11b5845f190675e93ac12639c272e4dfec130032c2bbd7bd18a369c4adf3c48bc0315cec16ac0b541e68646aea6eca6109a672d2dd97153aad95912c5c01e6f198277e37af85ebc10315421c9c0ca823dbe2d1b78c82c38cba4343c77ff7087625dddb5a109b571a69a3882414eea325b84703f5a52899f602ee05c80962418bbbad4c7320ee9589e0b4fc3710ceac664a61f06e75fd6744420fceae6b7f995c133693301cfee411a1f555bae361a55d3227eab0376cff048c217e43cdbfa6f6ad666841396ff3671b7e9201f44bc118b2326f717bf9d359b18f991f29855080489e69b778b9992e74108a17c51ccf0144cf5b43d7033df00a14c0b9c0478b7363ffe743029f1d2ee6d5618222142925cbef67daf835ae6becd8b63ebb7ec531bbcaf9869c1abc748ea0bcc3aff524863b89c3e9218e37afda60705c95947491abe8c2d3a3129a1fc756be5700e6d1a42501842484f057d1f3b71195fd9210fd64b0ee8a16b53faea733bf63dd8bdf8aa2e9f39443d8f63f3fd309966a50d61c7bec49c9e694274e8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130766);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-6385");
  script_bugtraq_id(93203);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82367");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-smi");

  script_name(english:"Cisco IOS Smart Install Memory Leak (cisco-sa-20160928-smi)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the Smart
Install client feature due to incorrect handling of image list parameters. An unauthenticated, remote attacker can
exploit this, by sending crafted Smart Install packets to TCP port 4786, causing the Cisco switch to leak memory and
eventually reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b04d6eae");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82367");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuy82367.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '12.2(55)SE',
  '12.2(55)SE3',
  '12.2(55)SE2',
  '12.2(58)SE',
  '12.2(55)SE1',
  '12.2(58)SE1',
  '12.2(55)SE4',
  '12.2(58)SE2',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '12.2(55)SE7',
  '12.2(55)SE8',
  '12.2(55)SE9',
  '12.2(55)SE10',
  '12.2(55)EX',
  '12.2(55)EX1',
  '12.2(55)EX2',
  '12.2(55)EX3',
  '12.2(55)EY',
  '12.2(55)EZ',
  '15.0(1)EY',
  '15.0(1)EY2',
  '15.0(1)SE',
  '15.0(2)SE',
  '15.0(1)SE1',
  '15.0(1)SE2',
  '15.0(1)SE3',
  '15.0(2)SE1',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.0(2a)SE9',
  '15.1(2)SG',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.0(2)EX',
  '15.0(2)EX1',
  '15.0(2)EX2',
  '15.0(2)EX3',
  '15.0(2)EX4',
  '15.0(2)EX5',
  '15.0(2)EX6',
  '15.0(2)EX7',
  '15.0(2)EX8',
  '15.0(2a)EX5',
  '15.0(2)EX10',
  '15.0(2)EX11',
  '15.2(1)E',
  '15.2(2)E',
  '15.2(1)E1',
  '15.2(3)E',
  '15.2(1)E2',
  '15.2(1)E3',
  '15.2(2)E1',
  '15.2(2b)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(2)E2',
  '15.2(2a)E1',
  '15.2(2)E3',
  '15.2(2a)E2',
  '15.2(3)E2',
  '15.2(3a)E',
  '15.2(3)E3',
  '15.2(3m)E2',
  '15.2(4)E1',
  '15.2(2)E4',
  '15.2(4m)E1',
  '15.0(2)EZ',
  '15.2(1)EY',
  '15.0(2)EJ',
  '15.0(2)EJ1',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.2(2)EA',
  '15.2(2)EA1',
  '15.2(2)EA2',
  '15.2(3)EA',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(2)EA3',
  '15.2(4)EA3',
  '15.2(4)EA2',
  '15.6(2)SP3b'
);

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuy82367',
  'cmds'     , make_list('show vstack config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    reporting:reporting,
    vuln_versions:version_list,
    switch_only:TRUE
    );
