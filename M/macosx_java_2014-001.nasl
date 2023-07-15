#TRUSTED 5f3dbeff6df42d18c0f83e2abcc95f3f3f94397c22179e2cc1750fcd63477e48253f92da3753271cccf548372403fc201549bcca491a6dd3aa7608c4bb5f562ef1ce718285f045269014937c527b5b1203fa283e253b38b38163dd32540799a7c0a5bd96418b3918def9f4b2b5ab173f9f9ffe2e519143a1acc3b6721845978cde831b94305589ea03da556ea779cdc89fda6a1c0347de50ffb0e9ff0e915450a916f0fa301497c1d106ed2629b588938021575508e61d45e9470bdfac440075a5db18b665d456fad16de2d64e8c2872a12119286372ce078cc8bb94d19a1b0abc57917cb0a34d346b576f91858ff4bd9ad8e14af736f14645d29e5fde875503b3f6f997e1e9490171099fea1dc00d243d1d4c792cab7bf7df7f4028d00dcebc965ac8ad9ab9aa31fc7f3de14210d4ee6da2f85b4a056432ff048fbbfe28cc12988549ec660c01b22d266b0165565ca53a7fa23464d7aff65236722fca251e5ba9be0eab2ec343122eb646334beee4c3d1d3b553dc1b01c5ea94b4a618c404ea544e88c78a530d7aadedcb68596e1cc4a64e18cf655a1e76c35a55b23a1f6952b35829e2143e93bcd3e82100dd6ff3e88f709fd9eee96497bdd8e19bc33f03897bbbd3ce38ee4e4d0310b4e9f794d44bcdac7ab70f822dd9da49c5bbe03bcbc8bb8c092d619c8e34f3f04bc0c3aafa5e17b779dc459d3a7a559feb9a2596b7ef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78891);
  script_version("1.6");
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

  script_name(english:"Mac OS X : Java for OS X 2014-001");
  script_summary(english:"Checks the version of the JavaVM framework.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7, 10.8, 10.9, or 10.10 host has a Java runtime
that is missing the Java for OS X 2014-001 update, which updates the
Java version to 1.6.0_65. It is, therefore, affected by multiple
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox.

Note that the Java for OS X 2014-001 update installs the same version
of Java 6 included in Java for OS X 2013-005.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6133");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/dl1572");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2014-001 update, which includes version 15.0.0
of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

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
if (os !~ "Mac OS X 10\.([789]|10)([^0-9]|$)") audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8 / 10.9 / 10.10");

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
if (version !~ "^[0-9.]+$") exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "15.0.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
