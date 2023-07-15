#TRUSTED 7ca40364ee6c50cf07ca92cd17612e558205b19334c2d2158f509ec100402c95991cd6a0d852499aae4f9e63ff6cdc61b98dac6f95d8fe55992ffe194bc42f931bdeaa0ca3343af3f9eb773d2b2e4477d04f8bd8e73bc5bc6e6285ed5a7dc1f262f02def0f20064c9d3fe8f80e27d7f3e9027f619454bdb97ba3a303ba0c012bb3aaed4f7138d64718a15226b2154411004bf5efe712733939c1f60bbb9a322a3b42586246978b179090308acdad58c3c7d9a40f5d5e4b856762ee4bcb6778a4b3a83cb7393a5d011e0c8f531a6d5295c3098d156a199886d70af3a7488fec0d54754dda46e463bc25316be1d7e38f401d70da4b3fcd1e5839186b4d4c3e0a0987e6ad09f2bcf65394d7217d21cc5dca9a7d031d218c4b48bc5223418dafb4244dd2a1d55ff7eb42201a8626c1a94677ecc22e77082bcfbbce40b3ccda116260545e7ff8485357b74ab64cb107a2ed353a434bfaafa673df56b0f7672effee6c53aa5c0fd2b11ea9fa083e6e1a33a36b075f91521f92d653c7a7012fdb0f87ff73b172110b7fa1fd4a65c49ac8cdaf618db50d2f2c770346ae5e09b17270ce6d51b6d18eedcb493b3e6ddc024471888d62419a425cb2ec35018f2a095918f7a3345bff430b916adc891d6b517fc3ba5fcd0ac0d1f660ae3c826b489570456f29d76cd2859348196ded21a269b4c78992fd79becf85f2953b0bfe23f62700756e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153203);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_cve_id("CVE-2021-34719", "CVE-2021-34728");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48004");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48007");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-privescal-dZYMrKf");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software Authenticated User Privilege Escalation (cisco-sa-iosxr-privescal-dZYMrKf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by multiple privilege escalation vulnerabilities due 
to insufficient validation of user input. An authenticated, local attacker can exploit these to gain root access to the 
system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-privescal-dZYMrKf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17677418");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48004");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx48004, CSCvx48007");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '7.3.2'}, 
  {'min_ver': '7.4', 'fix_ver': '7.4.1'}
];

var reporting = make_array(
  'port'           , product_info['port'],
  'severity'       , SECURITY_HOLE,
  'bug_id'         , 'CSCvx48004, CSCvx48007',
  'version'        , product_info['version'],
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
