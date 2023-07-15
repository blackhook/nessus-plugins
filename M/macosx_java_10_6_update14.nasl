#TRUSTED 19b9b38b051e65d4665a6668fe7d036cc741ed04b7425c4ea900ab0e46aa0e92ff143447efec38f41b1608ba53ca69fc92f3c820b3fb61f4b17b4fb06b1fcac6b2448d34ca94ea8843b2328b5f489ea711eb4c2f85f59601d93833238180eba6f295fd329c1bbfdead91dc8d6d7085592a2129a89a96ff645f550c9dbf2f2eb81276a0026aac2e12e79d57119478c9692c1cca45cbfdf5a322ded8ddeb9337c7c85b7d0a256f4cdaaf5e076dad217194dd16f1bacc59717040711722f319ec8ac7c814850d41dd77996d430510afb263f38ab435065f3854d4e25fe5f3fe98c8f18fd003fc36b9cd05cf2f798990547d544f55b8beb8fa7f81e46c0c1c178c6a1114854d5adf3e373fc5b4201d02ffa2b4cab849b727c699f4981df3d431abfa0ea3b0653ee3ad2e2de4b019cfffeebe4198f4de637318ea1b62069eb1df22e3989ef07f89f49e963dac05ed1a727ce34ac4f7698f598b5c0d2657d796c8ceb8a5ad098a133319b5d6b6adc1cbd3007296b06e73f0d9e9bbea78119c3d5a24dd50ac0b020a1d3290f99e02ba3a611f43d6bbff675357d53a1746a9e93dee3dabc07c48703474a588291d3fadf6ff3d111be358a67a12c7ebb7c941951b77568acfc5f98289477bca1ff2bbd31ad16b884fadef25a7202b61a4a65f7e5d247a8024d668b5f462201754c8a01c1d036e49def72921bc4372780a19db4f916e943c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65027);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_bugtraq_id(58238, 58296);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-04-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 14");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 14, which updates the Java version to 1.6.0_43.  It
is, therefore, affected by two security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox.

Note that an exploit for CVE-2013-1493 has been observed in the wild.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-142/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-148/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-149/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u43-relnotes-1915290.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5677");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525890/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 14, which includes version
13.9.3 of the JavaVM Framework.");
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

fixed_version = "13.9.3";
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
