#TRUSTED 2ae213a908e1a96e7682d9d48e71e287db345013a8b633e70c2c39f96332e606bf8e340910f7bb0b6a2fabd7331df693d888e7768105b6adc8956f56aadb3f285cf4a68712bf24324177373be597c34479289ae4bf720dc7065449f2d8cbdc3fe744e55de5bc32f9531d56504d78719442facd2d51b2d5156ad76be653b607128ec41ffb7fc9b995d1662f8551e70d8d6dd4f8ea7fbdcbef4db9cd07cd8882adf4ef69ac675f9f47c2a2b69306ab3d8fd95dad84f5febcda6b34373220ba7caf24465bb8e6868f406d45cd1aad475360b730f8a75ecdde76be53e90e5740606f40448b0dfc26a236ecabb7f3201057193c44e5d7947a4bb2c5cfb96e5adee9dc1d8c7d74c7450a8bd687a2f54bb771172d574b98da06fefabf1adad584f46ca7472418e88a8694d011c614977bd89e4e0a3b919287008bfc90cfc023ff2de619a5c9b44c2334e0027ed0b18d1eb128e4ee64f30bfe4ada0936df20b7d5bd73f767ddd8841c67068d11feaaa1857794c76f928fef0eb8ebff7fb877acbf8a73960e667c185e113f97f19a053a1e1e2ac8762e68d96f4cb2f979e3410ac42ec91082c2f11c31f08033d079f9be48699c88243fd85e1a7b0572829cfc18455b9b2770af535c27066d9b0857335255a882d8c516440b95e4c4790fd9d6e651ce574445c1da0a9ac01052578992cd31ccfb41a8ecff706c4c2f8e6a02d5cdc08aeeb1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134712);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0183");
  script_bugtraq_id(103555);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv91356");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-privesc3");

  script_name(english:"Cisco IOS XE Software for Cisco 4000 Series Integrated Services Routers Privileged EXEC Mode Root Shell Access (cisco-sa-20180328-privesc3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the CLI parser due to
improperly sanitizing command arguments to prevent access to internal data structures on a device. An authenticated,
local attacker with privileged EXEC mode (privilege level 15) access can exploit this, by executing CLI commands that
contain crafted arguments, in order to gain access to the underlying Linux shell and execute arbitrary commands with
root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-privesc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7ad8083");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv91356");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuv91356.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

display("piv: " + product_info['version']);

model = toupper(product_info['model']);

if ('ISR4' >!< model)
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '15.4',  'fix_ver' : '15.4(03)S09'},
  {'min_ver' : '15.5',  'fix_ver' : '15.5(03)S03a'},
  {'min_ver' : '15.6',  'fix_ver' : '15.6(02)S'},
  {'min_ver' : '16.3',  'fix_ver' : '16.3.6'},
  {'min_ver' : '16.6',  'fix_ver' : '16.6.3'},
  {'min_ver' : '16.8',  'fix_ver' : '16.8.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuv91356'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  router_only:TRUE
);
