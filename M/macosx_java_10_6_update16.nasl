#TRUSTED 5c4d1e6c7029b73ee1f103ac7aa50ca815f36e332b58576f30489541cd0dbc6d887383df12a0760572ead1557dcfe4f96897a046a3182c5f1242ce026f2d3a85cf99716e4f6bc0eed250958ad7f246c7412687f6b29a9ce856972f4199286968e952defc8fb0191a03e80c4747564ab917501d0cde44db14e4d1f97ee504d670d6ffcb45b23f8ea1d904f7205728f983d8b2e71919d958e6241b47d3583ac20de56ebef377fb03bf032ac702fa35c45cd8ba3b1d3fb0039d02703f904ad56c2265779a0956a493576e0332a032a326c5963dc6c4188e24822f61233f28526721a3ed9a113ec0dc507bb28585bde857dfdf89100959bbc9475cd3d4a6a7a95497a707462344008dec4bcb7cd3543e1d22c0b12bd165926191284e8a8d396c40d2b52f587ee87e46a8c5d569d62cd87d84a824ec34e761f3babac2e1bf9be8f229ee2a7f5147c539173f402f60f329869bc538323659784be14e641e18b6588491903db7e1c48279f27640a0540a3ccacee5730d67326decf1329251414488be0310c83f37f2fdf988caaca081060d01a472ca17d5f925f37d31a102632e04984aca0344d4a5e25ac5fe40ca34be7a327c7e74799986387d39663c6481989c7f0c7e7c8267804d03e0ccbe2f9229f485f1cc1b5d4f5b8a33b2bdbc572b37e86135f30935dd600eb5c70c5c21599c91d84f0a721cd378eef7fcc1e617ad9d62129b
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66929);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2437",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2445",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2461",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3743"
  );
  script_bugtraq_id(
    60617,
    60618,
    60619,
    60620,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60631,
    60632,
    60633,
    60634,
    60636,
    60637,
    60638,
    60639,
    60640,
    60641,
    60643,
    60644,
    60645,
    60646,
    60647,
    60650,
    60651,
    60653,
    60655,
    60656,
    60657,
    60658,
    60659
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-18-1");
  script_xref(name:"CERT", value:"225657");
  script_xref(name:"EDB-ID", value:"27754");
  script_xref(name:"EDB-ID", value:"27943");
  script_xref(name:"EDB-ID", value:"28050");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 16");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 16, which updates the Java version to 1.6.0_51.  It
is, therefore, affected by multiple security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute
arbitrary code with the privileges of the current user outside the
Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-132/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-151/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-152/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-153/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-154/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-155/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-156/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-157/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-158/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-159/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-160/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5797");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526907/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 16, which includes version
13.9.7 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
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

fixed_version = "13.9.7";
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
