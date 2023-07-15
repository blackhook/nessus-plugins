#TRUSTED 9dbe7cee161c38b420c8384cda14d438b052b5a03322032621c804bdf1e105d80ec315ffcb2bc7e32bd2a1c9ea2ef09dcafc4d614df37d41c42f396e87f01fac4de4b528eda41f51c0513afd39ec1d9fd41a6a028c2fe3ecf971eba48bf3ceb6004d798cd212ac413914da85f1e34180beb0ac1696471ae7a446ac4c9d43b24c0ae63171d07e203c9fbb47b14f4ab889ea128bbbec22e9e5e0dad5530f741d36ce661ec8e6923a0b6bc727b455f70a48177262a2f54e401fcfaa25606d45e024dfc792660a4742d64e1dd6147da6c70eaa765fa17b39e20032d2ad1f35a2e7edaa9370694bcbaa9ed80c1536194341936e794cdc44d29b4a332af39b1d5b222fa171575bfe47e0014f82a29a586cedf093a4e5e009e21cd1635ade544bd7cb9594bd73aff7dde17360ae7f548bb2cc968c47836f81ee8c266de45aff0be78b116e1d7f2c661f56f9fa8ecc574d7b33bd47176a925e27fa97f4a987f9fc565df54658fb5206f1917ebc8ac6eb1fcaa7ea2a0d06a8b49e181882702b31bcf38760662c599c5d57056aed72defbf8b2c4af7f3197e3a5d79651841c127acf6b7ab442096f35aa2c56136ccfcca6034c46f2c4e03c2c8d2bdd49eb378956ed9ae22a0ca2ef476348047f6b8f7c07adcc6a42c46802146b99d33f30aca7c05d4cf8a045bca46d214a4528b0cb36e862ad2bc2cb44b7b71491eec931b6af3b947f4be4
#TRUST-RSA-SHA256 2c90ea5a75f0ba5a31aabfd3ab0713354eec46f553358370f1034da17fbf81f23e487dab521576de6ff7cd11f06dae5cfb27be70197b7a749a6b94e5f616ba22239dd8b270f7c90878879d82d1eb662e1dbd84c3714e475956915132e367d15dc4dad6705ac518f2daeab8807766e3c249f81b13eaebf7dd1bba11ba315856e90d80d38d1b03ced890769d45aa02fc53fa6adfa008338d8da9400047b9a2a99a88cc28be978e1a144ff92e8b84273f79451400a2dd296dc8453e96d52200b647c633c4e11f7ebf094225a086fa942ded2ae382b742728f45ea64a76f0c995ba6b99c8661146a2fc1a4febc47a79817a8bfe491d803abd55e8652661aa5480ab7de49e3284dae96944ed04191b5386ea3551155f8b15401d15d764cbce1e2add17ce0e2a7a863c308985edfe69bb09a4f26f9ff883612d4c8937d8c1606c7e742ed550d6a9c3fe0c729d57abedd4002c25df12f3e4f27ab23f2018012bc49f923880e1c314b86087688604d18f7559f9758234fb14d3cca586c8a9d2330aa56943172520da78c4fb641c333f6f52948072012a5621f42ba6c8be28e2c1ffa0f2ca2d613cf7e0ef4b70fe83153ffe975284c015d5577038b466084f8f576f8b5320bebab32d0c047df4182c4e42054d3a7afce619cd895048af2410cdad9b9be6a950a629d5d0f831dd25cf3ee7d77d4359053476621d822a2a880cb2a9ef72cfc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125032);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-1862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn20358");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190513-webui");
  script_xref(name:"IAVA", value:"2019-A-0158-S");
  script_xref(name:"CEA-ID", value:"CEA-2019-0315");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web-based user
interface (Web UI) of Cisco IOS XE Software could allow an authenticated, remote attacker to execute commands on the
underlying Linux shell of an affected device with root privileges. The vulnerability occurs because the affected software
improperly sanitizes user-supplied input. An attacker who has valid administrator access to an affected device could
exploit this vulnerability by supplying a crafted input parameter on a form in the Web UI and then submitting that form.
A successful exploit could allow the attacker to run arbitrary commands on the device with root privileges, which may
lead to complete system compromise.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190513-webui
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?220946d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn20358");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn20358");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.7.3',
  '16.7.2',
  '16.6.4s',
  '16.6.4a',
  '16.6.4'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn20358'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
