#TRUSTED 41ce78eb3d7f4e07178146a5b7de4e6821098129abf73817f037bc16cf1e6e25103e9559584c7cc38519d756c33b8214130569d2ec760dcccc3fbacb48db74ca21ef39b0390bfb732ec7da8510b2ecffc8672e7eb17335264d00f921732cc5b47b0fb3f9d0c7b5771baa2f871864674d1dd21605a6ff86a2bc6f81dc155818aa0ff1ab805032cd7d49a3be078d1705fcd6ebdcc8c258af3ac8b3296b339d57928b8e71765199bb261ef24435c019bdd491b82a00ad0b98c856a8b717266a6c1a8f6557a5b4d45e550ebd6aeaa7fbeb03350b7829f0f0dfb8fd39f41d44d975f23386df81cdfbde48cacc808b1e4ed4f62a363acd0287c156685d785fe02b42201df9a3704823c183f4cfb9f166ac54e4443c7b8ac6ad0665b42482705ed117b8f49cf7238915516523d186ae836a17e2ba00049b64e733cef262bfec5c570cd3c7f3b458dd6fd91f63bdb40fb5843be4042344b91b69d02a12596b99f9cce052f062a0df61b6fb02fff931002605b6132f37310812b80502a52719a60fd3f4c966b5a8c45d8803c03d4b1821543dd1352891d76bf0d3856dd97166f0659b7da7bc0f0d8b3e82ea5e3286674065168b58103ab4823bb00fceb7e5a4083415bd405f6315ea4cad20be6410f1a808556985a8c3a2f34e1ae5acbc7629eacafa7079f36de9cbfd89a2d85be24fe3f2121b2835adbe30ad46f55003748aad5182841c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64699);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-1486", "CVE-2013-1487", "CVE-2013-1488");
  script_bugtraq_id(58029, 58031);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-19-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 13");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 13, which updates the Java version to 1.6.0_41.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5666");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525745/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 13, which includes version
13.9.2 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.6");


plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "13.9.2";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
