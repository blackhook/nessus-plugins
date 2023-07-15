#TRUSTED 4c1aeb3d738e3b407bf8fbf523a268afc9c419ed95d1d12a6017b486e75563170d06e70fed2952d1930b496dac853e154479aa2ac117562961f0caa027e0b26c99fa0bae67f0ce2a6c7569c35e4567c0f7644af89d7a49b1c8d11b11e2a915f6823fe9150cc51a36a7bbd957ac32faaefdeb04a15bc163526bb5bce0f5d1fffe9d432444d443334f5d75c193080805e67800bf09272f685751079c3aba166c74d71141b78b1da62a0f654a5596c17d151ef3242a1a316f1df5d06ee20f71bd9a1733565aecbd066c625e83a239182b016fa9f994030164460d4f17e372ab183066caa8bcc4ace25eacf60b44feb7588a984106b8eedfa8ff15bc1158fb9054e1634105a5dd6a138fc81a1700299afa90e50ee75160462dfd847186f809583c9edb064dc99749eb0a8c6c861a8778d29a7be869099f348058de55cb3d4bed840e700e2036449e0c7955ab12a126cceb6110bc30dade4c92b0d3f3a0f65ad081f7c7ebd61aca96e01053e293e3a205a479e7b93e9f95198853ee42a0620aa88c354f98e3ea82d752e63aeef654837b41e4a1017e01e3e4c17bb749d596a9d5d26b3ec521fb9606e151fc7fc79887200d1d64b543a7ac4d7497404d9ed525a624d8e435b9132d536a3308fdfc9caee99fab10982a645d6a10d4f5b9dd202512207e8ee3a1befcc1b7bbfb5112484988c3224c197bed5d73c11b50d0e2332100a6e5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77053);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3309");
  script_bugtraq_id(68463);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj66318");

  script_name(english:"Cisco IOS XE NTP Information Disclosure (CSCuj66318)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device potentially contains an issue with the 'ntp
access-group' which could allow a remote attacker to bypass the NTP
access group and query an NTP server configured to deny-all requests.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34884
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d368fe89");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj66318.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
# Per the advisory, IOS XE affected:
# 3.5S Base, .0, .1, .2
# 3.6S Base, .0, .1, .2
# 3.8S Base, .0, .1, .2
# 3.7S Base, .0, .1, .2, .3, .4
# 3.9S .0, .1
# 3.10S .0, .0a, .1, .2
# 3.11S .1, .2
# No specific hardware conditions
# No workarounds
flag = 0;
if (
  version =~ "^3\.(5|6|8)\.[0-2]S?$" ||
  version =~ "^3\.7\.[0-4]S$"        ||
  version =~ "^3\.9\.[0-1]S?$"       ||
  version =~ "^3\.10\.(0|0a|1|2)S$"  ||
  version =~ "^3\.11\.[1-2]S$"
) flag++;

override = 0;
if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  # Check if NTP actually enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "ntp master" >< buf           ||
      "ntp peer" >< buf             ||
      "ntp broadcast client" >< buf ||
      "ntp multicast client" >< buf
    ) flag++;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuj66318' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
