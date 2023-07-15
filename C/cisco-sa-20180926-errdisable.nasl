#TRUSTED aec804eaaeb0abb6416b256d79203f4939e27a72c9409b404a70cdb774c53196e7497611828913fe19ca260aba3eff362cd3e81a75d1030dfa37a9d2e02156c7f067bf5fc1db3916742f84f44666ccb6911dff35bf4c40e065f75329858e4df86cc3ecce1f2b4afe28d1bd0ee77e884c36a97d553db7f38e5add2f911283835c4fe1be8a5879ab1715ceddf0badd0cc2783e7b67281fb8eed9c7b2903e2e8e90922e71de76f0eedd514c7d690ffe496d6118678587a6c860f0dd071e4fcb0a6b878bd51c7c45505764a58d278a140a6deb959276b61473c7d737412556c0060d389453ae7371c89fe1cb0da06b692f488cfe1601dcb0de74d9b48074a63ec8a2394da0fd9e4194733703d1488a4e4d2d0e84d5437e2cad737d580b8b445fabf7f93ed2f3d027f8d30c78e04e1ca1e4333d0f24a040415f0ff97f71c28839f4e84a6f6ad5d0a69db5a9c57aaf8cdfc886ef51166ecb9f5a266d45d0cab679db483af0fe91b359b368838da09a8d815324b19e81091acd8fc46d5dd52f436918f6605ae0f48350c75c0d3585a5115ca031f49a1a5eba41c7910864bec098589e630e96428f5277375224036a682fca229b0eda1c7a8911e79a9cde1e6df381dbceab5cf15abee3f54f1fa4de4482552b97bd738a99bae79fa97360b500fff3cf4020928b12464159a3c2aa0e9e75522bf8e137833afed408013439992f64783637
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117946);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0480");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh13611");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-errdisable");

  script_name(english:"Cisco IOS XE Software Errdisable Vulnerabilities (cisco-sa-20180926-errdisable)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-errdisable
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a8eacb6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh13611");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvh13611.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0480");

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
  "3.1.1SG",
  "3.1.0SG",
  "3.2.0SG",
  "3.2.1SG",
  "3.2.2SG",
  "3.2.3SG",
  "3.2.4SG",
  "3.2.5SG",
  "3.2.6SG",
  "3.2.7SG",
  "3.2.8SG",
  "3.2.9SG",
  "3.2.10SG",
  "3.2.11SG",
  "3.2.0XO",
  "3.3.0SG",
  "3.3.2SG",
  "3.3.1SG",
  "3.2.0SE",
  "3.2.1SE",
  "3.2.2SE",
  "3.2.3SE",
  "3.3.0SE",
  "3.3.1SE",
  "3.3.2SE",
  "3.3.3SE",
  "3.3.4SE",
  "3.3.5SE",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.4.0SG",
  "3.4.2SG",
  "3.4.1SG",
  "3.4.3SG",
  "3.4.4SG",
  "3.4.5SG",
  "3.4.6SG",
  "3.4.7SG",
  "3.4.8SG",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.1E",
  "3.6.0aE",
  "3.6.0bE",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.6E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.7E",
  "3.6.7aE",
  "3.6.7bE",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.7.4E",
  "3.7.5E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.5.5SQ",
  "3.5.6SQ",
  "3.5.7SQ",
  "3.2.0JA",
  "3.8.0E",
  "3.8.1E",
  "3.8.2E",
  "3.8.3E",
  "3.8.4E",
  "3.8.5E",
  "3.8.5aE",
  "3.9.0E",
  "3.9.1E",
  "3.9.2E",
  "3.9.2bE",
  "3.10.0E",
  "3.10.0cE"
);

workarounds = make_list(CISCO_WORKAROUNDS['errdisable_bpduguard'], CISCO_WORKAROUNDS['errdisable_psecure'], CISCO_WORKAROUNDS['errdisable_security']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvh13611",
  'cmds'     , make_list("show running-config", "show port-security")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
