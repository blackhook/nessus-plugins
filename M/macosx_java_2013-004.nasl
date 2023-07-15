#TRUSTED 24896cd03bbb83e2c3a8cb60c27cf3fe2400ba5921d83023594e6b4596c50b3790f80c2efe85b2fee3f60ea340ee7fb7180e810921688ff733fc8b0ccc3a4c5965225b047ad6918b0cb6bccd18939cd191ec9e5ee1b9df5d5d85856a168da4c879dd7ab5096bfd8a67af5064ee84cb25886262d33e7f77ecd51a5569868e3631be4dcad6cf9a26fd0ab35402f786c47f71dc8718b75686cdfe3daf338e1e8e770530c519a9a5edb5089e27228a0550e38b55e9950c46a84df740c685efd2c2f0f9b6342ade41843879b3a0eee6532af0af30c230219af8ebeda24bf4d87a89950e3b293720106915bd9bcfaddf680246943012cf41a75a9da74024e4ab9a40cac293ad9e565507866495d80667e9a2b1a02c07263733499d21de2e3543aac9f01b9b67898e92470acc58c02fe411b7382e5cb7ceed46524c36110b2f5e0509d7e31ef5cf6bcf19a318cb912af61460da87d11bc0711d6b3adf81260e63d6cd7b7a2d137f129b4726c3f6bf5d9a7ca65b3d74637b0383d10a0ea58a67c75f4f48fc6dd6cc95132f7bc6ff3700247ad5fcd05bbe9aaa7b5071456692ba4cd036ee3414f788edb4977a51df4515a4e1876a634d59768b660a6a969d5a094f0145a86dc9fae923c2f84ffc719b951d0df653ba2ef0385ed6ec21e3ba1a327b0e4e5c6c66cddde657913d3fae2c4168a63ad342e88e770d92c148ab2744a9bfa0fe6a
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66928);
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

  script_name(english:"Mac OS X : Java for OS X 2013-004");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-004 update, which updates the Java
version to 1.6.0_51.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
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
"Apply the Java for OS X 2013-004 update, which includes version 14.8.0
of the JavaVM Framework.");
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

fixed_version = "14.8.0";
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
