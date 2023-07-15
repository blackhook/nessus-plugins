#TRUSTED 1d73a472815a403f2186877201a807fcacfbb5bd646e71063b284a80f8e8a54fe53a4b7418961fdfce946d2459048cd4357a4d0b3a59b92913f4604a565ca4166b325f42439867d9b0c0b809d125bad020e025d543605e4eb4c63ae7c620c4b3944d0d8e46fe7e054f562f70f44ebd62e4b9df8a2af8e73f64c9d52731811ad7c456cfa04e3310ce67d5f279e1ff25ed22af5c6acacb313b81654720e8678e3eb1d19350815b4ee8e55ff49afc08d68c1c04d9e0814d3e1371fbd7e5875bd6f4fb21ff60ea264990809ca521919f759bf85f0f53ea656f880fb5f1acf433a3e788293c557af64ef431cb5742a74ec4dcac98d89db44bea69c9aa7ffe670510efcce61986f8b6052b697ff3c3d0ab04c98197fb8b14172a5dbaa414d4f810db3781a9eb901ea2787a22ba68673cde7a842cc28f0282d5ab5fbe82f5b4229f2bee8c088c5842183d509d8801ab3c9ebe6e50d4cc57cef63ffc0e573c0104beace21177ab255f06e80db212596fabbf82adb5718caaf9f9e933cb73b6b4ff1e32dcb56984b7dc4271ff32a138f10f6acd5650581616c89dfe7d7f0e52ca2faf5c2c835a2b10e2084ff03c6d8248a90348d0872a30dfec25c96f9a5d4beed6e8089be383f0f916990675d05065340384d5f65c58ab8df0cdd97f97dc25c99854f43a2a393df1372820d34f70fdd43423e4de25213936becd3c85afbdb8a17ed1cf5a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65028);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_bugtraq_id(58238, 58296);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-04-1");

  script_name(english:"Mac OS X : Java for OS X 2013-002");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-002 update, which updates the Java
version to 1.6.0_43.  It is, therefore, affected by two security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox.

Note that an exploit for CVE-2013-1493 has been observed in the wild.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-142/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-148/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-149/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u43-relnotes-1915290.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5677");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525890/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2013-002 update, which includes version
14.6.1 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) audit(AUDIT_NOT_INST, "Java for OS X");


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

fixed_version = "14.6.1";
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
