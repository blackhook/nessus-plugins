#TRUSTED 726c3395c3e681b3e5d56423299d8db1d6efc673d89b6087e7324157e9d2a7500a41f2c8a29ab37e1d895b268d9c29d12528197f7484d084b155341a0a9d882252b1c9c7a53c8eb0e60bab1b57736282b597026be1968d24255c8432094dfa0b0e6e6f2d23cac9993e1c3c625caadf375e9c4a64969bb7509e78bd08dc7dc5e7ce24a0be560622831cd65f042e1fcad68b250793c24b4de8c8c32e5ae0b1147a8fb88604fb1f742d60f9bfd2aad310471e4d8719b41f78a5c32ac6c87fe0fbd5aacb39f91d2ba94e4dbf9d818e5914dcc8a629d4ab5d8eff35bee9765ed1a5074c14a755035752a62e6372d27a70482eec67e0cbad41f36ce6855a52a3ba027d3d8a378c6f0f64fe60efbde56746b535058e6e97ae7e0bb7bb6da33ee1752bf3b94ec636de24ffdb979ff68d41584aa22cd3aabe6936486d89d922c3e35dd219126edd64e3d203c381d62cd294cfd77dd2a490b459fe9e6cd710579df00400023285531cfdfd57b272467658ff85433618853a1db71e36cb5deb55dec5f1a09aa4fc01c751d19f340e2889465cb8c3ff0e9cacb05d8a959afe5148323e95c46bc30ee5b2d0a047826f183d2eb3c79374041330063749e96fa882faafd128b29aaaaef6cc63a3f92cebd192ebee0798dc366124fa75e8072d90586731e5ec2c939eeb7878a6b6644c5d40d44747017d05d30d637f9b775b32f6a5e310d24c7265
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117956);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0469");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva31961");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-webuidos");

  script_name(english:"Cisco IOS XE Software Web UI DoS Vulnerability (cisco-sa-20180926-webuidos)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-webuidos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cba237c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva31961");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCva31961.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0469");

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
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.2.1",
  "16.2.2",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.3.5",
  "16.3.5b",
  "16.3.6",
  "16.3.7",
  "16.4.1",
  "16.4.2",
  "16.4.3",
  "16.9.1b",
  "16.9.1h"
  );

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCva31961",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
