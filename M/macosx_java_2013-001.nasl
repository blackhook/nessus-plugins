#TRUSTED 15aafaaa62e7c10191185c6b5b912b18a6694fd57f0f5c6f813ecf32146cb960968169db77de33d4c4b83f8118493fdbe596a5882a5d0c0aabe81a689e68b4ecc738cc0e892f7189e3f2ecd9cfdf38e4622a5b3fe5fb1b8d543a197ab7517f9c92ed4c9b79a5e8894c34d221960370f62530ed52314b025df61f2b9d50e9fe2d551268ede417427cf79deebc537080c6dd45a8fcc1765aed6e0a268dac23f4e766fc1aceb9c9b8a95289c062b68d7d2246873fef24e91cc835da7bd5abb4c75ff3788c07585c1059389367f10a658ec072938996ffd281e831230bcc78cf794b2b6974a87c106d7a712f897fb199c7600a0841efe06462bb432646e2ff476433a583107ace3e03b896a01b5578da96e945bf8ed34860f6329c3f24488b928eda6e1909e644cfb44eb20a96f4962c69b2620173e8a6fb92e62105b103f189848c905650f26e32abc1581143aab99fdb29bd1464bd7ff6c120347cb03b3af0afb1a40eb2706f3dd0f19ef0825c2777bc7bbbc54edd368cba53aadb1076de8773de00ae6c447811118111047dd5293c977dc4f2267c4d571c02b3d9e7822d269348819de32615c8100ea715df776a9c29f040c1ccbd0e0d47342e477d27bf9b53b2a4276ddd1e3ad122957cb83a69852599d20e2d31e71e001037f7b350eecefd283ea10df10d6ef03e9873d31d659ffa1fac900a717be71bf3c7e53077e5ea271a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64700);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0450",
    "CVE-2013-1473",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1481",
    "CVE-2013-1486",
    "CVE-2013-1487",
    "CVE-2013-1488"
  );
  script_bugtraq_id(
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57699,
    57700,
    57702,
    57703,
    57708,
    57709,
    57710,
    57711,
    57712,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57719,
    57720,
    57724,
    57727,
    57728,
    57729,
    57730,
    57731,
    58029,
    58031
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-19-1");

  script_name(english:"Mac OS X : Java for OS X 2013-001");
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
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-001 update, which updates the Java
version to 1.6.0_41.  It is, therefore, affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5666");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525745/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2013-001 update, which includes version
14.6.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/01");
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

fixed_version = "14.6.0";
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
