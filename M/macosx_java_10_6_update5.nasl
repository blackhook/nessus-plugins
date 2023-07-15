#TRUSTED 73169c1100c5b7733272c4bc3045052020470d09d3d58dce7cfb00d4da497f216bb1e4c9171c250e21b5ee61440afe391c3ac808ab0e37d951cc5a2779659b4d58a1388c1ebbfc3e696596c49bc3173e24ad03ed5edce533448206c9652de6e64fc28b959c99a454222018ee72530ec7f3767e962faa3b1b52c52bcd1cac52855b0417aa67be965f0bbf36b38553ba1ba1ddc42e44fe4fd4470921eee0106d1b4026103d2a55f78d1477e427be717ac364bc1a17cfbf62259a87642cdec6971c370e3864ee3b68d0712775f495d4e3012e03bc6b33d7ce35da1aed34fab1dff0570a148329288c9cebda62834dd712040309d996c643520e9abcaeda43faf8c968431c58d2e1ba67e385704125e67fb981d2948ed2c7b2b8ae5d64b65735b5b02719b83673edd5c68f280fcca18c5f0c1767c95cda40d1fbaca0a513b15895f977846742af0536d92f059fbf73c257333fa3b10b037ef3593d55fb666e1ef931677f50571b67735fab7582d4a51033c80d26834ad974076ef297c8cd0a810dfdff1e534122c7d44157fc2f424cb6f385f7e7ab7de8f4c9628c7d9e60bb010937c2341a102f31fa5411d58aacfd8974dc7570170894c0fe47b2c94bf41e4914eab433ed4aa459a7597b58c54f53c386e1010298566ee30488957a3e40ae66d41b598f8de772142dea47defc385ca892574a129d164661d5c714381664ca979119
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(55459);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 5");
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
10.6 that is missing Update 5, which updates the Java version to
1.6.0_26.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 5, which includes version
13.5.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os)) 
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

# Fixed in version 13.5.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 5)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 13.5.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since it is running Mac OS X 10.6 and has JavaVM Framework version "+version+".");
