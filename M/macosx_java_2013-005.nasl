#TRUSTED 471652c5c1408e4d5d412e68b8292998c37abb78a5aabfc803760c2fbc2dbada180421a8fbb1f9d874d06503e682c6aed5c959735804eb7a5261f64a89079e93cfbae60f3c7fc3b3b37c31f15d08d8d5ca6275f3b173b1278887cafebb8dc36371aebd06af99858a140d6450fdd424051f9bbac79bdcc3fbff5991af4b0a9895978f7306c771234a4e002298a6934748b737e58f40479294a2349916298057039ba6a8fb9a1283fa53c88d876a43a643c7acb796715c226dde18b0132b67da67ff8f1f12acd16d8de22e24a1fdf036504e6adbced455d339fb5272043f7a30d85cf2d9e7f85590fa5f0797b5878455199d9601af0411935f599c7379db78714777cf4f92f17482034dc2cd5a5c0b208c84a5439f9d783fc57bd3af21f7fea435b9f3eb9f35332653c02c45c0ec5827ae8908a1a9f3a6f9aa306f10d3669af9c4a19b90171bc5253eced1372c825e91ca8fd2f9b954f57c4fc480c30d354ae25a65a56211ac9df3ee7356f775b3553bd0a03c983d19361c1490fe90d3b170b7291c91e05f64d55a9acb0ea73b90ab998f8fe0946768f4865b5fcdc681ea2786398989b99a218d492a1b4c65e31326a06e74d6ac301b6616a9babe9191afbe7a9f6da3d2ae576c1f67cc670bdb1ddd3bb3b183cd910f71359c6a85b7bd99a7d3fc6fd9b219047397a160e6cf1fd8505354c848194c9b57a59285ce6f7dee035cbe
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70458);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2013-3829",
    "CVE-2013-4002",
    "CVE-2013-5772",
    "CVE-2013-5774",
    "CVE-2013-5776",
    "CVE-2013-5778",
    "CVE-2013-5780",
    "CVE-2013-5782",
    "CVE-2013-5783",
    "CVE-2013-5784",
    "CVE-2013-5787",
    "CVE-2013-5789",
    "CVE-2013-5790",
    "CVE-2013-5797",
    "CVE-2013-5801",
    "CVE-2013-5802",
    "CVE-2013-5803",
    "CVE-2013-5804",
    "CVE-2013-5809",
    "CVE-2013-5812",
    "CVE-2013-5814",
    "CVE-2013-5817",
    "CVE-2013-5818",
    "CVE-2013-5819",
    "CVE-2013-5820",
    "CVE-2013-5823",
    "CVE-2013-5824",
    "CVE-2013-5825",
    "CVE-2013-5829",
    "CVE-2013-5830",
    "CVE-2013-5831",
    "CVE-2013-5832",
    "CVE-2013-5840",
    "CVE-2013-5842",
    "CVE-2013-5843",
    "CVE-2013-5848",
    "CVE-2013-5849",
    "CVE-2013-5850"
  );
  script_bugtraq_id(
    61310,
    63082,
    63089,
    63095,
    63098,
    63101,
    63102,
    63103,
    63106,
    63110,
    63115,
    63118,
    63120,
    63121,
    63124,
    63126,
    63128,
    63129,
    63133,
    63134,
    63135,
    63137,
    63139,
    63141,
    63143,
    63146,
    63147,
    63148,
    63149,
    63150,
    63151,
    63152,
    63153,
    63154,
    63155,
    63156,
    63157,
    63158
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-15-1");
  script_xref(name:"IAVA", value:"2013-A-0191");

  script_name(english:"Mac OS X : Java for OS X 2013-005");
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
missing the Java for OS X 2013-005 update, which updates the Java
version to 1.6.0_65.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-244/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-245/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-246/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-247/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-248/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5982");
  # http://lists.apple.com/archives/security-announce/2013/Oct/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74a1d7ee");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/529239/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2013-005 update, which includes version
14.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

fixed_version = "14.9.0";
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
