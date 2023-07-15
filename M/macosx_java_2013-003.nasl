#TRUSTED 83f2286a9abfb4cd35ad0bf21ba6d7e149a9fd5c5a570cd6cf4cbde17369f9dc308354db55a1234026a6cdf4788145d9e98d7fec4977fbbc0837efcfa522f47ffb49d050297d66733aced4502cc8bb262916312bfbd36367233ec83033cacada8bb97b51382461ceca44d0c1d460dc6a10c6f4f475aefeb4d2d3aab44a5823074bc142fcfdbf73dff53f1cd4ca724c446592c27cd0bb8fa828640bd56373b0ab5824eff673daed5011d5b3bbc89380f301ff561564230031e8508db303b383b1b027010de8db5f4fa060c7a695329ffa655c84b6cec004da2c73d47ef8061b930d0df56fd3d8b31981edee130cec1ab28caf63756bac598ec5a1d53e920961ada12bc73eba7e63bc48baf12b716d1812931e9ba9ea6cfdc262e5640901067d7de97eabf4e98d8da4595f5a25d04a433df1c67f61f3efb8bf465440505806efca3272d18dc07e74218361e1bb0935c254ff4d941d70a921e983a3192a1539c1a77f552bac431ed81f30d96211f3f68969d4990bcc8fe369849158db3204f5a75ea20bef2cc2a3749300ca6ab58d9368fb347cddea032bc5d147274cc7ee1e34669ba2eedab31f21e4b1d3541c1aa8cd9c09b41bd63d41b2f6ac83ecbc621a03418f096d545454258f3bf5962488f5df382288902e8897f228f36bf4b8e847624f2f00cc879114129253dc76b7911205f5349d620568bc632665a43f4126297550
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65999);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2013-1491",
    "CVE-2013-1537",
    "CVE-2013-1540",
    "CVE-2013-1557",
    "CVE-2013-1558",
    "CVE-2013-1563",
    "CVE-2013-1569",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2394",
    "CVE-2013-2417",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2422",
    "CVE-2013-2424",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2432",
    "CVE-2013-2435",
    "CVE-2013-2437",
    "CVE-2013-2440"
  );
  script_bugtraq_id(
    58493,
    59089,
    59124,
    59131,
    59154,
    59159,
    59166,
    59167,
    59170,
    59172,
    59179,
    59184,
    59187,
    59190,
    59194,
    59195,
    59208,
    59219,
    59228,
    59243
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-04-16-2");
  script_xref(name:"EDB-ID", value:"24966");

  script_name(english:"Mac OS X : Java for OS X 2013-003");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-003 update, which updates the Java
version to 1.6.0_45.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-068/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-069/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-070/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-072/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-073/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-075/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-076/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u45-relnotes-1932876.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5734");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Apr/msg00001.html");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2013-003 update, which includes version 14.7.0
of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2440");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");

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

fixed_version = "14.7.0";
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
