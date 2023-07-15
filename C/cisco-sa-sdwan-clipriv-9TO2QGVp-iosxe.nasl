#TRUSTED 8e8fa51a8712760fb208b663076df835222055b2e411845fc4509d1c53f6dabe43e604c6d2eb2c303ce6d6dd4691eda88a6ec627d17de448bf8505c10a6a3372fdc29e46ead0fa34589bd5155a7ff963add3221752d91f5151db4909681226f291879de1f3b03707e658aa32db198a0d131d50b13d19f6f5fb40f2ab09cac1b3141348aa57c8c735e25cbffc9ec27ec249eeea7796726686b88619355c4cb92f0745653b998dca1f0fa73de311a1fe9279eb84a99686376c8138454d5fb64c4aba5ee3abec0986a27e32a00e7598494b054879fd9791ad6a417390711a0b2029b891fffd1ecc2efb005ea3362f1181913fc50665434c6938ed925daf0a3027bfce1ec69747737bef83eff55ff3c441125659358ee7b49e0b15c806469d98407942156300e51aa97f3a0a413c2a05d6a30f05dddf8202561de0bd8bf3c5d214416c8f7d0ef629d019f4a9c7a93f761725e1d05453604ea3b71688e96266abc4a999a03ce664a9663d4a44d2e7e39a4b12061ab810f148e35755e96325d85e05421bef5a7248dae74b13a4bb20335cc210836f123e6da054bdbb27fbc22ae98835b10b043179ede99f39d69dfdfd63cac58fcb31af703caa55dbacc76039deb1210b75ccc4df6d0f3413b06f6f882f109b205b7e23a5c0d6e2ae0e9677efbe777bc03ba450897336272494156ed0ab17cc5051bf5e4bef341874b80c6f083e2cf8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148105);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id("CVE-2021-1281");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv65659");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-clipriv-9TO2QGVp");

  script_name(english:"Cisco IOS XE Software SD WAN Privilege Escalation (cisco-sa-sdwan-clipriv-9TO2QGVp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-clipriv-9TO2QGVp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a993be1e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv65659");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv65659");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.2',
  '17.3.2a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvv65659',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
