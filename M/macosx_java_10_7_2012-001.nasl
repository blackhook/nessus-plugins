#TRUSTED a0d0015f0a07d907e2b81a10525c7a8172f857635ad94ef3fca370e3ddd201eb68132d7ad08f3884172754ef052930748cb9019dadc80813666aa8dcbc0a01868a5542fa82bbaeb8fc16c195ee98b9043e55118ab7afee78864c4c395b1ea3b01ed42c8541934de174b62e5e8b75379b90e2eefa93f4e01acc861a3b94cfadb16de8a9b7d8925db7ef03bf9202749b70bca95968889ba0a5f2f109e1c144412d668398088a3e5820d799421ecac8b4c89e61c2d7226fdf4c551c6c0d9055994ea67e6cbadfce4bdbae2fa3d31c4eb1d931435668f50f136dd4582a28d62ffb6a68675084fc23d9655e0dd086badef9bb10889ba9b1c8f07f57cb9210b6b6455d9424e18b3bd0c3c1515974e7e0e50c817f5b8a09ec7fdb3f5debd60b993442290ebc863f7d52b10ffa5caee6abdf0c2e1f998e7fae9e2561102fd641b2c7dc9d5ef626e4957fcb627a0a367fcf4f98e7ce966b3dfc953d9916f2e7467041f2fd647c54c6915818534b249f24e49ddd028c7898b4ff8c294ee25cf214defa3421d9e5c1ae155384fa401a02917555c689c26a92f26298dd9f70bc30c1fd987eaa422bc85b6f7b44e403af701d7c54b16effd2120f17edbd31f43e4dd1c33875e99dfb6d1665a2ece1a5726bd0a481d943c100191c9dc1b37705587213d6031a578a6fbdf31d24fd7d3b84b530ff20ee1066e494fab81ce86b8de6ffd8d1928df5
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58606);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2011-3563",
    "CVE-2011-5035",
    "CVE-2012-0497",
    "CVE-2012-0498",
    "CVE-2012-0499",
    "CVE-2012-0500",
    "CVE-2012-0501",
    "CVE-2012-0502",
    "CVE-2012-0503",
    "CVE-2012-0505",
    "CVE-2012-0506",
    "CVE-2012-0507"
  );
  script_bugtraq_id(
    51194,
    52009,
    52011,
    52012,
    52013,
    52014,
    52015,
    52016,
    52017,
    52018,
    52019,
    52161
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Mac OS X : Java for OS X Lion 2012-001");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.7 that is missing update 2012-001, which updates the Java version
to 1.6.0_31.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5228");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Apr/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/java-dev/2012/Apr/msg00022.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for OS X Lion 2012-002, which includes version
14.2.1 of the JavaVM Framework.

Note that these vulnerabilities are actually addressed with Java for
OS X Lion 2012-001.  That update was found to have some non-security
bugs, though, and has been re-released as 2012-002.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0507");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java AtomicReferenceArray Type Violation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

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

fixed_version = "14.2.0";
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
