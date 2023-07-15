#TRUSTED 5c49582aed56df7ac7dfd31fc6d146dbb6412d3356a98839754f34e763f2730a98f1a86899e6dc0a1f998d5170093ea0f5e4123d03387792290fa0532ffa1b1637ef8a4984d0fcf5f5099745d79f01c3342aa737aa53c1690de89cdf56e6290c30e8ec175ced697f176c43f618fbdf4ebbf26d6da9a4dc18156227752c0a4d8ababbbdffe0b3c61e4abcdd93ddbd1fe122c9cfdfccc0ab6440678e57c0aa3c389f8d214dd1ffc28f867bcd3640f85d3db391f33cf944ad8374b16b295d218c1c0adac1cec9bf46ba5366be378159a6e5e00f14ddf518744586f21540e30d8aa47000648fe0d186396f2f14c668882ee7817c84b843aae8e9e54e871ffe059f5326d0f9972b6f025955427a68d8c534943471a04fe9d103c9a81b03316e6599b3f3ed8fb31e21af23d2ff0e65cce3354e05785819616990d7e4d6309a9a938498edc9799dd391e8e0e433fe0f1b77cfe5747417ec2783666aef62f7e8ad3ead72e39b8e80f636c635eb701cc5be3cc61d40ce060f5ee48e4e32c282f2cca629f5a7f824ac6936e88da93b9c17619320d61f0ffdb12cca8705f1122ce921d7df434becbbaa7b3c00dd27d22e1781f0d965977bb08ab252e8fc82c460da6d8a48fed26593a92d6ae81987a365202c42de4b292e0c3973fd38ea006b6b46931e8324641bada9930f8ce79e9d222507e723c2786e47f0dfa6d4063addfb4a7b91d4f0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93562);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1347");
  script_bugtraq_id(85306);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq59708");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-l4f");

  script_name(english:"Cisco IOS Software Wide Area Application Services Express DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS running on the remote device is affected by a
denial of service vulnerability in the Wide Area Application Services
(WAAS) Express feature due to improper validation of TCP segments. An
unauthenticated, remote attacker can exploit this, via a crafted TCP
segment, to cause the device to reload, resulting in a denial of
service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-l4f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba0706f1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuq59708");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCuq59708.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln     = FALSE;
override = FALSE;

vuln_versions = make_list(
  "15.5(2)T3",
  "15.4(2)T4",
  "15.4(2)T3",
  "15.4(2)T2",
  "15.4(2)T1",
  "15.4(1)T2",
  "15.4(1)T1",
  "15.4(1)T",
  "15.3(1)T2",
  "15.2(2)T"
);

foreach ver (vuln_versions)
{
  if (ver == version)
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS', version);

bug = '';

# Check for WAAS Express
if (vuln && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show running-config");
  if (check_cisco_result(buf))
  {
    # WAAS Express
    if (preg(multiline:TRUE, pattern:"^\s*waas enable", string:buf))
      bugs = make_list("CSCuq59708");
  }
  else if (cisco_needs_enable(buf))
  {
    bug      = "CSCuq59708";
    override = TRUE;
  }
}

if (empty_or_null(bug)) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : ' + bug +
    '\n  Installed release : ' + ver +
    '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
