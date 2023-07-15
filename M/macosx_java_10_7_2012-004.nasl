#TRUSTED 499272e84b734d237049c4316d75bc99f1a70d008bffaa82d85cbf01e7e816b7d52b60d98b12a9ff6e0dc394b0c1b7b8609b367912224202d8c9504a5a55529829b3073b0de75883f5f79c86e3809feff480930097b96665c8e776ca4d63d6978ea2f19ccc9f00c8f6754dd8234b535e46752e94ea667ff9547cc601f62bd20fed1c4a56ba2f1cc17e917dcc547ac0e44c8f14b7820edd0503bf9dacc0e6c1a0f24c8201f3504868dc7459d53dd1187256419d0da992ff3fb1156a1cf69a4032ac04835e28673f0a3373ae4d5e1c38b9e39c1ee67570845a15331495d5c051a6ef14853a5c52ffa2533fe6753faa2efa83704a81e6b5f7ae8b92e1445bb55faf9746a378ff5b050ae09e116e4bd1ddc79e6621a854beea6e53f2b0f5097a4bdc717e0f8d354351c8bb35bd52a7d465f45a9d0fe50037b050cd65b4135cc083bfd8657d4faf689138909df9b2da9e060eca6f001d511651e80028b66fdfd2db2cc1ece36c6a05297106be63cad4ffbd77c12e75f7b5b0d83ccc263a51ca217e98c07175c66c428a4f220b70e7bcdfb60dba378d1da7a48906fb08d6cff11a260cf71742ac55948cfad29470a31b5c90eef8ea9741fbdb7cd561694a88160fd65c5b596d5b8263cc46c7850712be2d882ab3605c31ef1860ec21246f4c4aaf83a8680af24ca81cb0a4c60f258ac9df7a2142de7ba634e92adcef7f632051346bfa
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59464);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2012-0551",
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1723",
    "CVE-2012-1724",
    "CVE-2012-1725"
  );
  script_bugtraq_id(
    53136,
    53946,
    53947,
    53949,
    53950,
    53951,
    53953,
    53954,
    53958,
    53959,
    53960
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Mac OS X : Java for OS X 2012-004");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 host is running a version of Java for Mac
OS X that is missing update 2012-004, which updates the Java version
to 1.6.0_33.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.

In addition, the Java browser plugin and Java Web Start are
deactivated if they remain unused for 35 days or do not meet the
criteria for minimum safe version.");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for OS X Lion 2012-004, which includes version
14.3.0 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (!ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) exit(0, "The Java runtime is not installed on the remote host.");


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

fixed_version = "14.3.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.7 and has JavaVM Framework version "+version+".");
