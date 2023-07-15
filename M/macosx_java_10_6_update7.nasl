#TRUSTED 63da245abd7fd8472f1f375ec3001218c781110ed3ef86fc484d99fcadc1e53368c485a056b8e7c6ccabbb2b3b6d233c5e9d895bece118f7767cf4a274eabf36c33eab41776314540922bb3b85796aae7f6b7daf14a0ade5338d49c499ef1dbd39479913f5fdb05728b6af943b7aa652be72386908169c9a7d36fe1ae2098be134fedb49be1befda364d82655aee8afb9576ff4ea136f5f3654a75e05add32663814ffea4d7494eb373004f71ba95bc249078b4d84baa0831d141515d48b47abde653142646342ee92adaa985db359cabd0afeed791fcb3e7f94932eb8ef0b7d933ecb4fe52f89f142a454454ba8280e7d359c6a80693360fe74eee52ad2b565b98a13dcf57cd6f6aaeaf8ff482ee15127f0cbda9f1ab0f2c19b74b4efbde13c8a6024f51455305978c5a7bc9d75281bd64a1d1a96c71ed87298c6a2784ea18606fe5f87cb8d831c85c2fdd485140ea2d5647c1778b60ab0362faad440abbe89a5f7e4b9777a22eaf24d28025ad2765276e3ca2040a925825bd0b023ddb68a8c412ca4c32457666dcdaa2bff021ec77231d327ad5e64fd77e101e457bc56c0aab116f1651924978c6149662ef8b6634e18775eb18e22e6e2ca11ea836d4968226920afa52455e9b119e2eba1bc6780f3c0dc66b77fca80552519f21864dece4407db87655b71e81bd5bb6c8bffacdd2975f556040b8a9455cf684459569e583c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58605);
  script_version("1.19");
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 7");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 7, which updates the Java version to
1.6.0_31.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5228");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Apr/msg00000.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 7, which includes version
13.7.0 of the JavaVM Framework.");
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
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

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

fixed_version = "13.7.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.6 and has JavaVM Framework version "+version+".");
