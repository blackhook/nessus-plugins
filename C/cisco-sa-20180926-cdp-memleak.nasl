#TRUSTED 99da2f48fa48375261d4a7e8649037a6825fa7a011ab8930d3036465d1e6418db0121d4c533f429a162b97d0adf0b0be799fb22a0c392bcaa322c3a9c40174cba1a5b02de0d041812ea2c2a0dc20aad8d8c18c6502a6def76a19c5f6f6b2dbb5d0a41cdefc99698ea87229ba81cb011289234dbf2e361f5a93ccc83ba6c0311797786299e9d6ed6c752d819cc7569626cf7b83f731f63b5683790483d3947d8be730af8b4f0a187a04b209b56205e5eb34c42b050ab418c97693cb8a2bf6862427bb528fe4a550e9a6d71facb25b72c50465d7c27c3f057de884d4c7d5516a28e5b9f6f747bb85e9c646a36df93942c9ede3a27b0cf9460bf6ca42681822db0209301b9a57a9ef4829f9f0b68b6e3d1d008ae13dae6a2353292b80484583b192aa202fcdcc0e7ea27122b2616f5c754ea7fb50da564f92c315981fd156eef217b2f7517278fbdc41cb4609f6107d111643e86e56647f6ac29a12043ce2600617729d4bd2fd4e2320e8e004d4c82d36a44a69988d21b09bae1964a8e3d5d4ea02b029112b670bc1b8986966db9008ca4dc935cdcfdd350dae250c5aec7e4bf29189c0da050bc710727d3f2802da5b75c73dbb1ad5e066707421e98bd40ceca16e4f267ad59fd38418973d510f2f7fd127e85176a275f71cc42caddfed6ab668dc3e5b85f3e950d0e537a2654d23b385fd319ee5c029c7e5936ca024d7825f0d50
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117943);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0471");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf50648");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-cdp-memleak");

  script_name(english:"Cisco IOS XE Software CDP Memory Leak DoS Vulnerability (cisco-sa-20180926-cdp-memleak)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-cdp-memleak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f417e796");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf50648");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvf50648.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0471");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.6.1",
  "16.6.2",
  "16.9.1h"
  );

workarounds = make_list(CISCO_WORKAROUNDS['cdp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvf50648",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
