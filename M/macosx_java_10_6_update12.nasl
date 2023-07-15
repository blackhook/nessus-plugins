#TRUSTED 71aba2a0e2f4e63315e794f391e4a0e4d7fd721c3ebc1c18033791b6d166cc875785c6aff3d3974ed3306f7b6dbc7c44a0e02ca08d449312a96a6f56767d34cb49259478b919867ca4e07fc7fe8bcf0364b33713c2ea57400ace1a2be8db295c176985e1b2abd9fdc379480dbbc8e05a9992f306a466cb9e1ee7f78230484ca5c2d153673eca9bb9cea934af0c6176adae15bfcc150016475d8b3986eced0a546e2acf6e90247137c2a87b624561848708a42d1ee112320df5c6e24e0244e65978b76170ea3d71ef19e0331aaf468c9b1b4d700b1eb7ead8476ee963d9be858851401fd3ac36e5f38f5ed6434bf3618adf923883cfd0f3a46880771f31b5578a6ea7ad062cbc38c85a25d674d70400cc8b958d055040150a96672033e2631b00ef04b6915e92a76aa893d159975c065b58c8e73bd3928eaf15d66aa938b52cbb7b38a13cf00901a36bf386baca68a7c12f983bc90a9cb6ba3344eda4e0aa53f6d5cc086b92bcf9c9dbc2a8ce379ccdb5103e361088f68748106788a2f2473085d6b9a7174b7abd8d0df97bd1a1b7084b4c30da162ab3f8a4989f44d98948d107beb6553986ff2d690425e2f0825835a337b20514d83463ee4c27d7232f699da29d95d20410d7d217486e9e977a3e66cd89c6c5c85935cbd4d6d323393a208aeb1108687de8bad1f9220f59d1c7d4c1e8db87c1781f07fe339b65ff70a83314ff
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64472);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0450",
    "CVE-2013-1473",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1481"
  );
  script_bugtraq_id(
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57699,
    57700,
    57702,
    57703,
    57708,
    57709,
    57710,
    57711,
    57712,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57719,
    57720,
    57724,
    57727,
    57728,
    57729,
    57730,
    57731
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-01-1");
  script_xref(name:"CERT", value:"858729");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 12");
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
is missing Update 12, which updates the Java version to 1.6.0_39.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-010/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-011/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-022/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5647");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525549/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 12, which includes version
13.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

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

fixed_version = "13.9.0";
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
