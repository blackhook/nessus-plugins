#TRUSTED 97fc9572fc48c7eb808c3192e744b767d36b8723ecd20d94e797e84c3d051af6d7b3c95b69976aeb9299796f7104cb2e9eabbb0abc68b9de091530540079e70bb4c906a42abe5944b8f89d3c1fa4af752ec7f67ea08010cdda524886a5151fcfd298c9612899e5c2e8a84146657f44eadc8fe97303bd5ff258f982b2a8c62383de08989d595e4e6046cb6b839f4fd7f5ba79a236f0e06e35dbb99a956c6111de9bb35191b42aba922e550349620711f48b6472e35104d8b301bbf867057d9767cc4fe55059458dc54915adce4f1e09a878691b543955a9f511cb0ba499dd64cbd914467e875057f504774dc3f625387a74d460b4e5544e581be7b15f6b00a24ac07c324b9556ae98d8304fd7309ae86900f205f0adaaa8ea2a4602bdd8f8252bbba7430201534143e9c3a2c3f64446bb798c5b646bf8d0d1f34bea00929b5a1cba61923fd1a8640a25d6be751cbbf26d267ed74eca96c06c1317d2d5952b8f91f5c56ac30ddf6a241f5843eee173a8a7fa941c9caf9346a68fa5011e90d89ba07118b02f8e7ef6331c9ae658333e3e4ea212527436bff84f1a8ffbd39269efe98e7e5f42ce50bcb64af8d3dbfe9ac930504249495623cca6610eeaf96638c64f22e6123897adbc19a65618e39a75f23013b606e664d3e8b77fc46e2eaafce60f24b5b1b32f363c0a3a2486370a6143fbe26b1c4e2e2067a22dfa83e19db09d01
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89083);
  script_version("1.14");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1329");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160302-n3k");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy25800");

  script_name(english:"Cisco Nexus 3000 and 3500 Insecure Default Telnet Credentials (cisco-sa-20160302-n3k)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus device has a known set of hardcoded default
user credentials. An unauthenticated, remote attacker can exploit this
to authenticate remotely to the device via Telnet with the privileges
of the root user with bash shell access.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-n3k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d406d865");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy25800. Alternatively, disable Telnet and use SSH for remote
connections to the device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# only affects nexus 3000 / 3500
if (device != 'Nexus' || model !~ '^3[05][0-9][0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, "Nexus Model 3000 or 3500");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

flag = 0;
override = 0;
fix = FALSE;
fix_map = make_array();

# 3000 versions
if (model =~ "^30[0-9][0-9]")
{
  fix_map = make_array(
    "6.0(2)U6(1)", "6.0(2)U6(1a)",
    "6.0(2)U6(2)", "6.0(2)U6(2a)",
    "6.0(2)U6(3)", "6.0(2)U6(3a)",
    "6.0(2)U6(4)", "6.0(2)U6(4a)",
    "6.0(2)U6(5)", "6.0(2)U6(5a)"
  );
}
else # 3500 versions
{
  fix_map = make_array(
    "6.0(2)A6(1)", "6.0(2)A6(1a)",
    "6.0(2)A6(2)", "6.0(2)A6(2a)",
    "6.0(2)A6(3)", "6.0(2)A6(3a)",
    "6.0(2)A6(4)", "6.0(2)A6(4a)",
    "6.0(2)A6(5)", "6.0(2)A6(5a)",
    "6.0(2)A7(1)", "6.0(2)A7(1a)"
  );
}

# Check for vulnerable version
foreach vuln_ver (keys(fix_map))
{
  if (version == vuln_ver)
  {
    flag += 1;
    fix = fix_map[vuln_ver];
    break;
  }
}

if (!flag)
  audit(AUDIT_HOST_NOT, "affected");

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_feature", "show feature");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"(^|\r?\n)telnetServer[ \t]+\d+[ \t]+enabled($|\r?\n)", string:buf))
      flag++;
    # 3500 + 6.0(3)A6(1) credentials can also be used with SSH
    if (!flag && model =~ "^35" && version == "6.0(2)A6(1)")
    {
      if (preg(multiline:TRUE, pattern:"(^|\r?\n)sshServer[ \t]+\d+[ \t]+enabled($|\r?\n)", string:buf))
        flag++;
    }
  }
  else if (cisco_needs_enable(buf))
  { 
    flag++;
    override++;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
