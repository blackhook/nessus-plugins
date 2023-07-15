#TRUSTED 017fcfc68959c5c864a8c2f87b7e7e41fb08cd6b6ea38fed98dd66e8ddd5c0263d63d30e926e36f940b299c69fa0209c6f8905ada1e25b38ac2b64e1b4ce55dc3efd7328e2b80b394b6e033e918abbee2b341e812a061163e8f93a5c13835f62fb6a6ae1dce0b5873b7b3f3f7085395acb146636441c0218d2dd8d6a260fe7b5cb1dbd10670b08aa361060ab2cdc283aabaf4213c12697dae1b10637448888390ceff64ee76f2a804d7265d2f0059f6b189743a8222e1be561c8c2ce07642c2ebe09fc5f746bbb19c4763b442c382e976809f7170e922e79b22f3469f7a3997620be327637da052a6630a17b7b6ffa5d14aa0fbca6dff1b4c2ae04456c728260c1fc517ab02a26145596e6002c3ba6bde2a271dd0041141fa8073f06eb5ae2a2293dcc89d139557133adf0a756885c94ef92aa5d2ac6f83113010a4c04ff19395df3543583744f01dab686f6b0e79c0a68e4313c0746bd79ea21b6f1c359c21efc7e5055f17ae84235ddb5918d53873e02fa7525b669aa3b159b5bdcf796a9c15ba62599f84a8c139aea296e19e0a63df8c039b12d6e67efcd8ff4137ba68261c041d8d0c0547bc5268146bfaab1bae30b0dd3c1684dc2c8fe45cfad46ce6fdc84be2437e3f262cd6947fb5932269ea4167f88a4352f5126b407081f07e678b0d31f89ad143753ea535f7edb18cd42fc306fece045849f11d079aef123e02ba6
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62595);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3216",
    "CVE-2012-4416",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5075",
    "CVE-2012-5077",
    "CVE-2012-5079",
    "CVE-2012-5081",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5086",
    "CVE-2012-5089"
  );
  script_bugtraq_id(
    55501,
    56025,
    56033,
    56039,
    56046,
    56051,
    56055,
    56058,
    56059,
    56061,
    56063,
    56065,
    56071,
    56072,
    56075,
    56076,
    56080,
    56081,
    56083
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-10-16-1");

  script_name(english:"Mac OS X : Java for OS X 2012-006");
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
missing the Java for OS X 2012-006 update, which updates the Java
version to 1.6.0_37.  It is, therefore, affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5549");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Oct/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Oct/88");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2012-006 update, which includes version
14.5.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Double Quote Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

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

fixed_version = "14.5.0";
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
