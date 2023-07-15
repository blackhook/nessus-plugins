#TRUSTED 44d128c37649a5da7c77581f08339167741d86c55f99e13f42d0e89fa2db614f0d9e4540edf937a3ce014795ee6ae113acf08acba64dc032c3647e492bebafa5c49cd7f40dfc1c0969302877c2652004417ccf96a8d687c274fd16a5cd9d5e573a6de48f5c222e436c900752a6f70d2268e9066f370d5cc2bc6c3db2eb13e9a7559f7362718c991fd8d7f02fc504394ba02119df4ebbe90ae708feedc64384cfb0b672044c8281e7514747b213cf4b1877f23cf50ab3a9d41a5d9cc2cec827ff68c50e852fe189955e08244b37ad510ffd82ec15facc9abda2f7ec47943073cd0f1fb47fc9b10a8bfb46c0dae4ea0838752bd2673edb45c86b34d4b436090401b4a5fe93b6d5a39f5738182e1d6262a7ab4e0ac909a8d5afee54f800730bd14d4be98a1e3d30fd810647d51aea2dad7170bc0b3d63386f990c9d72724aa789f39383936f3684775db960faa2990bc61d70ea9d70dff8cc7e7d48d58fb24e521fe8f3fb64f876a5a89f05492d97ebe057e417e25481b8c3a0602de1ad7f6f09851175c7b05ae8272c4faddaf358034f6b6e385f7053b4535e5076cf7908a98c9010e9798b9bd544df1c26c56a3b4404fb0607adb9fdfa3e8eea7dac2b5f0d0fc37d950867aa8f4a1e6f523803dcc844491276fb56a2e279e65f365baa56680cf63fc0ffb8fb81678f3bbd0d9250399f7f1c8f9205eecbb4ba4e39c7d2acfbfcc8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103566);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2017-12230");
  script_bugtraq_id(101036);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy83062");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-privesc");

  script_name(english:"Cisco IOS XE Software Web UI Privilege Escalation Vulnerability");
  script_summary(english:"Checks the Cisco IOS XE Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1efc8374");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy83062");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuy83062.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");

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

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.2.1",
  "Denali-16.3.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['http|transport']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuy83062",
  'cmds'     , make_list("show running-config | include http|transport")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
