#TRUSTED 18a7b94faa2a0415ea5eaf296e06b8fe92134c4e7fb53fafcec39879ae6a8bc8a1567a5d3091ca5684ce45384bd44b2adce0ae4a1624e1e6e70c3c018cc5c11b9e5621a947586b076af1edc5b1cf293a592e179bd0f654a0f1e74b10ce3b15e6d8285fd6b98d6fa08756af8f1b602d613049d6c4d5b95bf8fb4e951564a49e35116e9fe893e27ecceb0ec1478f253657bd60a3893ec27e86fd65b2a642c75dad9e43b26c959ee9af62beb25871004854544b287f5c3db4ad6d86f04c69f89287fa91816a1bc8361506c853c80ef8e1ebf0d12ab0d6a7c0df1fcb18be6a9d045f6d93075c9c102a6ac21c1b4593f8ab6a88a83ee1dced373fe3806c457a00e803c8e79ad1fecbc499c0e9b4a709885669733d6c92d8e3315e3c6f6a336c4b2b0513f19a2cf8c847d92b0b4cc8960988e80b782c8fcf3fe89f457cbea910f1cc35e7a72ef174e9e443cc5e5d029e30f65e49f93a95a0f1ffda82d29e9e4138c803515d4acb565c8f74efa29fa6d97e48ccc3ae6df78c858260f9c6c2ef29839ff2ae8a9aee6e856968d57c9cc62b70cb858361382b3336a914d684d2497189d982b6df0817befb370de01fbc5a754a357c45c24e33d85a6d8ad4db02cb55aab69622268bad01c4908d6b62c2ac1f2019b2eed220c85f2b8788bd2c8742e31ed5494047531e4c8fdd8bf532ff2ae130c5e4e24c8d5a126dbf28df7e35b2b015280e
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62594);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 11");
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
is missing Update 11, which updates the Java version to 1.6.0_37.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5549");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Oct/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Oct/88");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 11, which includes version
13.8.5 of the JavaVM Framework."
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

fixed_version = "13.8.5";
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
