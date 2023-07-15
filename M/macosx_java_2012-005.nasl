#TRUSTED 54ae3b732da4778d511d371cb60b3900b39347da386bdba75b6cee9f84e8ee4355b4645c5ed979bbfae72c998a9c0a3162aa9175125dcb7bb1c9a6a954f74bd00a726adb850dee137ad7923c8055a5c829943f3ee1c231577dd114cb5d3a8867da1c3a71e93b943348462131102635d451e537b0291d14b3602351d4404718e03659d405dd63f6850f64baad8ffddcd239fc543d9fe25af36dc9c118d3c690a5e6561f8b1555051180ad837a7bdad917a4b766f57588e2c220a0b835aef650b2407e80c5836871885fda6f760a33e46e687550d99fc6454911e56c1dd8a52bdafa4d573050b6aef859170c1d50503fd004e5964d3b52899be67ee5298e3e8ec09a9b66465acb4f8794e194851ff4199ff05bd82683d16a2aadc808bec749a1b8d1e4fb9e61c62f6ddef8f64c8402c89e2560e1939198a3e0c8d4abf2eafacbf97d1984f785ccf478c2e82067b7c96a65ed5a038cb50261f9d5a2423510a799df46f20d446dfc0ab4db58b9eb0a8f5dafa6f5b93b4af99096d7b5da12a664b0c7a93835af1d87e65ffcfcf8e27bf4266e35ad3eb9952fcead19c16dedac02cdc3150f8af4693d610aaec0ce52811b013fa8358b6628f3f4f52fb2e9e69c8bb0029c48b9440156bf4dc3347cf5f952418a6764d38a7c973e5b07007f3e68fedacd6404001af6a9253b35bdf692af22f3c2bf14bcbc5b4463306f397a5fd94462d6
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(61998);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);

  script_name(english:"Mac OS X : Java for OS X 2012-005");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that contains methods that can
aid in further attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host is running a version of Java
for Mac OS X that is missing update 2012-005, which updates the Java
version to 1.6.0_35.  As such, it potentially contains two methods
that do not properly restrict access to information about other
classes.  Specifically, the 'getField' and 'getMethod' methods in the
'sun.awt.SunToolkit' class provided by the bundled SunToolKit can be
used to obtain any field or method of a class - even private fields
and methods. 

Please note this issue is not directly exploitable, rather it can aid
in attacks against other, directly exploitable vulnerabilities, such
as that found in CVE-2012-4681.");
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00370937");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5473");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524112/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2012-005 update, which includes version 14.4.0
of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_version = "14.4.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
