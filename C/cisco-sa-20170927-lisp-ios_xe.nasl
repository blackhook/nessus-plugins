#TRUSTED 5f6e0a92c8d62618d1b33813b0a4ec352964a6b3e4b4ca2fb1aedf9acb04eeac926e9bfaf23b06b352f1c9ce51585670277d7e3a3fa243ad92ea165037b3ded7e86dc7578fdd35c9e81bfef44126ead42db830ecd7e4f10c929cb2e9f8963fe403901d7b1e0316813a84e643a196cb43fef3f387891fdd0420819f3a85024ffadd3a5b967846f1b641d1b2127e675e0117a5a2208c94af2ec0290d464f0030bfbc0fee0346b76848183c5f776780166a78144915ae725be0fc2d6e82b4fcb41ce22eaf0a00973d8010c1afeeb6b3775853940ba6b0c64c27cbf90fc7768468f735055e63ff18ff62176aed69cd4b8781fe5fe4f38086e5e67dec6fc5f9c71065b9473dfed38e2aac0d05c62400740f0d192a303407800fac924216b51fe55df00f2071d3bbf145e89efb8e8923c125c0b6c8ffe1b912430e088497e0ceda1c614eef815dc455939a2833eb9a0edb5a86993f68b1d86c9c15f6f409b9ce7ebd5de33a15136c0be84defafb6e2aebe8025312be935ce7c52bfd74f6e5c6dfb3c5777380859b29f510b29ebed0996d1ea3a7fbf16eba31fb039326136117c79777a359061cf6edf50a3869ab16494feaf9e37cdc5e68b42937b5268948a619952050bd5f74a866adef5d03e0df5d6bf7211e21466fca580fdbe5e542fd3eb9d74128cc2fe2594db1ccc1149dd7f612806d4ca980cb374cb0486ae4e2c33d8b27f7f
##
# (C) Tenable Network Security, Inc.
##
include('compat.inc');

if (description)
{
  script_id(103695);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2017-12236");
  script_bugtraq_id(101033);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc18008");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-lisp");

  script_name(english:"Cisco IOS XE Software Locator/ID Separation Protocol Authentication Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-lisp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4aab580");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc18008");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc18008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
    '16.5.1c',
    '3.2.0JA',
    '3.9.1E'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['include_map-server'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvc18008',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
