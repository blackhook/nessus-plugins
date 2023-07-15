#TRUSTED a1b479f97e1ef4ac9bff3c05242780d367970b551a93baaca12d40bad4209ef092732fa49c57b96d3e715d2c6be3cb9f9ede40f2f5a79476c7f4a77b5369da5b8efcc01a9d02ae4c0704145349d028ce94b625ed7e22724ffa737d319ea4a0cd7fc05d477c1abd215611746042d92b86b0ec9d7a7329db1d2f354863e1f62c96f0a6751f80b43f8d55cfba04acf173fd761e5183ef114c866a54c9ca5939ef2e0c244258c695db30a65e2710684dda3805025ad03647638eb66cc86f0eebd926e5d37eb6f20f2734c028c3df0c2a045091d8be9dbcd675acc7537ecc1388cfe126fcc956f505e8fc4b46c7e975c0263ca4e36e14d1962b369c2fa172be0ec38a5215358e001e7ca3d3432c24e07619abe087d3d72dbb1539991e1903e2489b73acde9dadcf1da5f0d886c287710a37857002c66941466c21f30d37f9ba963a11b0929f1a2135860f2b4045bc425ea4c939129e77713e05f7cc20ad66770d18252e4021aec4b006abf1561bcae9c9458ea18f6b24f08105a9b005bcf67b182e7f15619f56a81e458b911c762b2a7a499b2591934a02db2d976f17811ea1b9c390ffb6f1985e31fce3885f2424e1dfad9634d28a485d502f694140249ef7b794d74ea6cd4cb694060456aee252278683d9db8a91c7bc80e324b6eec8f6341fc6d4d45b32eb1f2a967ffc97da7a8c275a04e601eb130b7ccbc654df940bbc23ed7a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131703);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/03");

  script_cve_id("CVE-2018-0315");
  script_bugtraq_id(104410);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi25380");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-aaa");

  script_name(english:"Cisco IOS XE Software Authentication, Authorization, and Accounting Login Authentication RCE (cisco-sa-20180606-aaa)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a remote code execution vulnerability in
the authentication, authorization, and accounting (AAA) security services due to incorrect memory operations that the
affected software performs when the software parses a username during login authentication. An unauthenticated, remote
attacker can exploit this, by attempting to authenticate to an affected device, in order to execute arbitrary code or
cause the device to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-aaa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47fc6762");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi25380");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvi25380.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.8.1',
  '16.8.1a',
  '16.8.1b'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['aaa_authentication_login'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi25380',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
