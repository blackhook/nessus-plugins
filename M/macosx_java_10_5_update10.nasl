#TRUSTED 133ec2520ab7d8d0f0bff348640d5d982a14fad7b4cc6f4a55db2d2cc1369930bdf29d9110509da0488cf728ef1c6dc73f9435172240aa53251a1886190ac08325619cb9cd32055f55a2ff06dee3c19642c5f349c61f64a5698b7e6d6c701856bc11d238d2c16fd464368dcfabab80378c88fe99457d61e2e8cbb30026b765d90ef50e09b552d40b964b5c4416342a9bcf50c0bc85fc95e173eb82200af569656c519c7cbe78428f71c0121474a4d52a71ed8183dc7b85074128a4493468bdd2a79348909a7fa17a7b99a0dfe7cc9ab0873deb143077b4b077ca591a33aae48549c9cf9aa4d8b10f9f3c2d8e6a30b97440611b85f1f239a6bff62c564c73dcfba3eae39751013e38a0c02a70fcc9f97d7120336564de8b8bc0c42e49f536e47aab21c8c9a4dace78a03e1c4eef78fc858ee690b0d5fc80e8e43870e367e32686ff2b326e37bcf87ced7c06ec216a16a968aaa3b1be57d37b335afbabe82353665582f1586a3c458035564c46a728cdd5dfa1515afd5e5c5ff89210316b071c5a8a984fb1173fe5d4d0f7a9fbacb234ad9171d9ed815d972fd170d0b671ab8191d5cb33fd4fb75291b49ec6eb9b2e9f990540693c2c31c011f985cc2bd08baf86027f283575f8177dcf2a96a2c818b30d5b55ca64ac1e2ab57eed50e3df3c7dcb482ca0965e06b057e2804b93c40b9e0b2197bfdfaa02af4110f1c8170f9bd470
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(55458);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0862",
    "CVE-2011-0863",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0867",
    "CVE-2011-0868",
    "CVE-2011-0869",
    "CVE-2011-0871",
    "CVE-2011-0873"
  );
  script_bugtraq_id(
    48137,
    48138,
    48140,
    48144,
    48145,
    48147,
    48148,
    48149
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 10");
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
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 10, which updates the Java version to
1.6.0_26 / 1.5.0_30.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.5 Update 10, which includes version
12.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

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
if (!ereg(pattern:"Mac OS X 10\.5([^0-9]|$)", string:os)) 
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

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.9.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 9)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.9.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since it is running Mac OS X 10.5 and has JavaVM Framework version "+version+".");
