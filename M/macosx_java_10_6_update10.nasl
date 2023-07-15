#TRUSTED 19a2a8f57794b0ce2a5be3cb5cbd837327e9e69a5f07d22de1643cf7ab264cd9b45cf6c7dfe638eb147fa61a476512a03978f09f2f8fe331dbe45bdd61d3fc8ddd8b5efa983584cf2ee5003ade4468590296dc77d7d0f87e713e31195e7297f7a0b86a874561de3c0ff4ec7c48881dd8430191b529dcc6fc2b70883ff0a90e0d3c59ea6ef9b188553b3a0ff4daf4e689d8f1e6353b7f96b0085ddd3390c40fbb675c7dd0dd36f3d47b7f1fe7d82be72115ecdcf6e79355b953f3a8a8c76803f7ace4a02761e776796343348bdabd7fc16900d90b3b66f9f715a6e369fc6f666f3ed99f5cb013ccd94298a245bd86df80ac63ebd75c7f5c413c0e6d0925d68515e33e6646d3734895b6bc9cb5ef66eba0dbd36f13fcbbe69921ff8cb756353252e32e550398a8e9b6f1aad25c6cca79c9b52c26fd24556c21fef6b3e24344edd0d19d4aa5a873331192508b14fd9f1973b448ab902190cf265d09c87917771dafebd955b6a7504675112da89ed456bb996c95b302ebe0f10191aa4430a9544916af7f43981de550da3e8d70bb1bc0c5e022ee4df6aa0ed560c4699255e29786004dd747b6e3dd03b5a41f738100e1c1f1a2f2379f06e9a056a9c7fd93c93ff40e29b97ab91ee79539554f57bb0f3ca3a55194dc49c61430597d6342ecc90befb307765a8aa00e0707e8928ba2db0cc8ed988f18dd189592e3fa5f8211d7492f19
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(61997);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 10");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that contains methods that can
aid in further attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 10, which updates the Java version to
1.6.0_35.  As such, it potentially contains two methods that do not
properly restrict access to information about other classes. 
Specifically, the 'getField' and 'getMethod' methods in the
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
"Upgrade to Java for Mac OS X 10.6 Update 10, which includes version
13.8.3 of the JavaVM Framework.");
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

fixed_version = "13.8.3";
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
