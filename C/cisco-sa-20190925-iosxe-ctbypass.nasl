#TRUSTED 2f76af94f7efe44dded7485201da8a7b569f50baae4528a56d1db439219d92dd6fd10ec76764d1f39f8ae4be2bfa130a5bf83c8bda6c9c2393784693778ba5a302970df79d4ce323b1b6f63c80004ed85f829c0d4718c5f3fdc6351f5f520499e29bf46cd272c3acc1f1d70b104788d0bc0dce0292f550a9cb815f2a2c0eeee2508aacfd00276a906821f906dbce1dd91e11e0da271aa078327d2dbf9408f2dd5a00378907be62193dd6e7f3764ddcd79033b9d7243160acf1b861626d1b47cbaa50780755dbbdbcdd1bd562d2bf4e32872c6210f55e73dadeb3a22aaabad9c4080654c37dced8a7633264997cb132f31c0e1619ee17a8af62c6fc0c9503875f28d9a01c9852695b5ded941678f0f8490371d5aa6171d4aa463f771577e9d350ca95c8b6068e4b7b8b23bf970b5e754f3687e48c55679738324d513e930ad9eda8c2e7920f6cf4e1a756d96574e263488180c14b4c48c68a4e19d865b8ae57cab508d5a3009e10d7b324bc0a3d9b4375af4eb636c0f3194c07f4311c96e545c912c19a69ed04c8644f4b63df414314f62f7bdda5229267c182903226f9a3ca02f8d7578b0955847409f9c221f8c29350c836c864899013444f4a592493d784a196bb350f6e0cd2e90dcd1d69b756b681d0066dbd0cd2eb245c0c8f1253cbc4b61fbfe987f828ff20b56e6145aad7e7345556aaa470d718caba164d537b45bf6b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129586);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12671");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp34481");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-ctbypass");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Consent Token Bypass Vulnerability (cisco-sa-20190925-iosxe-ctbypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability it the CLI. The source of
the vulnerability is insufficient enforcement of the consent token in authorizing shell access. By authenticating to
the CLI and requesting shell access, an attacker could use this vulnerability to run commands on the underlying OS.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-ctbypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10434195");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp34481");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp34481");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.6.10E',
  '3.4.6SG',
  '3.4.5SG',
  '3.2.9SG',
  '3.2.0JA',
  '3.18.3bSP',
  '3.14.0S',
  '3.13.9S',
  '3.13.1S',
  '16.9.3s',
  '16.11.1a',
  '16.11.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp34481'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
