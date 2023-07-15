#TRUSTED 4b0cb4eed4f864e08ce78774b9dcdfcb3c941cff4c773ebbea7dfbdfde3ed3de24f9f158e92d606d930df507996190db2645d8d993077c4b8245d8b223ecfdb57a7cd0ec8d315ea628fc755734d6c7c100eae307d0fc13ac1691e5d37117172fe2aab6bd8e6d93f1b5b12c474577e02f725f023680941a082007dbf39061706b4a08e36807c4c73ffd6de00ebe7425084782eb5b2ecd0000aad8448906189d3998c3e298b805f7f2e887642cd89b4527e9b4524df5fec4593f30a6e672c7e40e09a778197f9d3a07d39c6911d8220302468000c11e2148bf7895593b6e3f6ec09ba93e5c5f609eac6644e8f5f13f830f8c75b9376b0fdb027e49acbe7cb8ff9063863e2cb047bceb24126f3d5103065a8a6a146151e950a310662fb1a20a5b67c9a2ec34e8ce279aca8e89e9f381f1000c9865a5818e3611f0f17b6824d81c1e6301e2a4fc52bca9e253fc5abd1120d9f0fca27b6d35c4174f6cb7e6cb4dbea709e01605a266b5258df8840c37048d3eeed6685266f03366a8222ba550cf1bce782d8ac4ab89b938c48353fd41adb1fa3d2f1817958b489e006cacd7c12c4ca50089343dc43e0a72a3dd2b1d64c964b14b090879f37eb72a98c82b199187264e51f6ca493bdba654e5cc9175e74c2ab2f2218fc49f07d95723e1948e3d2ba5bd18cc3ac08697436ea291b81a1244e50f440938e771f3b37adf0154fc06a05bd3
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70459);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 17");
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
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 17, which updates the Java version to 1.6.0_65.  It
is, therefore, affected by multiple security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute
arbitrary code with the privileges of the current user outside the
Java sandbox."
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
"Upgrade to Java for Mac OS X 10.6 Update 17, which includes version
13.9.8 of the JavaVM Framework."
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

fixed_version = "13.9.8";
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
