#TRUSTED 5e74ec28290bee07bda1c16c19329bdb860938232fa41ebb3403897c502d30530505d63e1e069984c25f4839a3d1c430c9ad41a589be4c7db8a3ef28bef9572baa378744b4fb3b20224bdf45ebfce3cd21626254e75992c6070ff9922a43714c65931629f40883551a967c1a01d8115d0bca53321ac5584253298abfe9218812aaff1fa0d8b1c89f4604d96190f6062f66f3ea7ac2a0312e0fb2f6a5326a1b67bb9c4a17256a0797bfb8a085b6ddbfe282a47a242a3bd7601e05543c823f723ed9f4f6ad78ab80f441612e480a64ff2100b441b77144ba5801ff83a9b4e006c24aa6031c704c4905f23d47b01fa8a4dcb8b8776219420290e4075fdee18e1f050c1cfa497d974370ccbf59db905ee75a8eb9d3e5c935380a42318df64dfd4fb6e843b66d43727cacccf7278416ee7400ccbed3119b665b103ea741ef98fdcacfd7fc65f11924cbb11b31a24b492322944b305ddc0f0dc21aa0356661fea9848c2c14cc93cabe716313acc8d7c9af2bc50f70bac8a3704c207726c82b49311d9d54c0e316ec815a89a219bb2945d5fddaaf56bbab7e8266f58ce0d19c8371c513c6330efdb7f59ce643d61a0fff4d5d4ec2e46d6b04de3f78530726aa3871f4490b98d268c585d2a02f171dcb7e20f74d1075dbf7d6e8c6f54980a05836ad10e98866d5f200e592a38b2751a788f59f21bcf4640be9380199ccfb3e45cfd075c7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131192);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2017-12222");
  script_bugtraq_id(101035);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd45069");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-ios-xe");

  script_name(english:"Cisco IOS XE Wireless Controller Manager DoS (cisco-sa-20170927-ios-xe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
due to insufficient input validation in the wireless controller manager. An unauthenticated, adjacent attacker can
exploit this, by submitting a crated association request, to cause the switch to restart repeatedly and, consequently,
stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ios-xe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2904d654");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd45069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd45069.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = get_kb_item('Host/Cisco/IOS-XE/Model');
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affected models:
# Cisco Catalyst 3650 and 3850 switches
# A previous advisory had the last two digits both 0 for Catalyst even though more precision was specified in the
# advisory, so do the same here. 
vuln = FALSE;
if (device_model =~ "cat" &&
    product_info.model =~ "3[68][0-9]{2}")
  vuln = TRUE;

# The 'show version' output from the advisory contains no model. In case we don't have a model match but paranoia is
# enabled, we'll continue to report.
if (!vuln && report_paranoia < 2)
  audit(AUDIT_HOST_NOT, "affected");

vuln_ranges = [{'min_ver' : '16.1',  'fix_ver' : '16.3.4'}];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['wlc_interface'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvd45069',
  'cmds'     , make_list('show wireless interface summary')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params,
  switch_only:TRUE
);
