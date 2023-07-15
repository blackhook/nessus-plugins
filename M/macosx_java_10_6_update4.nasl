#TRUSTED 4d496db7e0a9e965dff4e0c3c6932f763c2db90e4796447c751e208289ffe7c316c4b67507751fb9c1040033a4d4123bbfb7baf136bb7ad4d06792528e25cc24ba4d055d80ee13b88830701f1e754237e835972ebc24d4e9ece0d1f561e2da546ff9ec9ff2dc062b16086897c31016e5abe313d76d7f60fc102247e3306b9f33dbde90ac35afb069eae430d04fb52303c8aef7dbaa90ff56b3425c9ba076b2aa75f06679768d1482383550f98194fd4d92eb60f0bb30ac6f2e855c8ada2ed7edc72d5eaa1ab46a1ab8438824997fd704cec9e85c2bc32463f6243e14c2f8163a56b716546eed8ae344f1177f47e8ddd96dee14cc03b3eb32093a25b278979534816330384fd77eb3f341c22a4a3eeb97c77d198f8086474601f9694f3e6bd765629ed1ad49240fefb1b80288839be5f25c62eec278be18eb6fb5901e5b550f7dcdd17e14eab10f8da4f507b18800762e81dfa662e74eac1be357805747b81ba1a298ab8dbdea7ec4da003d461e3c02d4accc636bc0ade882bf02d5c668fe2b325fb2e8e8adbfe2c70c27fc1265afe00f1d603b56852220c843f0fcdf33bc8ad768afa025484113825d2eb13f2a2294291f77ac645614eb10617b2e00813e6cfb155ec0d3117e21e1ff6be8e66a61b4d3147385ae9a28f6fdd6b53a618ed263601b00da6596f7cdf5da70cb0f5590217063320d90825ca9c865379401704d8af9
#TRUST-RSA-SHA256 a63b1db17771927d0580038601f4f26c869778b4a04666f699c6338090b7363a765afe7efc426e2750c4788d4619b6958c1aaae66183f32fd8720eac973f4146df813858e892b01418e0f15264a835f9ce2a1f3f6bd426029b6604f0533d6fc862dfe2f0a36d2ea43f9fb47eac0875c2ff9c37ee065850b516ae716f9883a0193109566abd53324e6e3f9f0922e7f6a77d233e71c8978fc74f68b6a0cb6b49aafc316b5d8604e8a282f48334c9b623a972d23585fd4fb80fabc744309e3d9df6028224a04c9bdeb6f6ac1876f2c4a56fea62b06f156badb73f30c75e892113eced5a701e322e6de19a5e7894bd4ad5d72adbf36683516ba838973f50e55b177c9fe124ee88d4b8c829c12eaa71c5c75ae4159b619f4acc8a3b4c8b7800b3b673f0cbe390bf8e30f721f6d103b96c8ec6859e69eccdba69f04ecf216537b58bfff146c71677f57948f05f3a720dba8d5aa21bc8cb48ef278781d2104510bea44e876cf026f948e130bc8f3dbf9f1ce96a985d538db9c901ce7bf3d85d6b07c0ea2757d9891ca03e50b706a17593c8138a0e5fb03e3df2b6b3a36f7ea450e1e521aaf3334e8680f45916772a998bb60ede562273b827af10e90bc29018e2a104de258f28236fb009b490f61e46130e86e6588415b0921f23c3041a915dffe32ec20dfe6709fce4cb67dcacaf2428e4c02f412e360a9e4a23994cf74537ae51b096
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52588);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2010-4422",
    "CVE-2010-4447",
    "CVE-2010-4448",
    "CVE-2010-4450",
    "CVE-2010-4454",
    "CVE-2010-4462",
    "CVE-2010-4463",
    "CVE-2010-4465",
    "CVE-2010-4467",
    "CVE-2010-4468",
    "CVE-2010-4469",
    "CVE-2010-4470",
    "CVE-2010-4471",
    "CVE-2010-4472",
    "CVE-2010-4473",
    "CVE-2010-4476"
  );
  script_bugtraq_id(
    46091,
    46386,
    46387,
    46391,
    46393,
    46394,
    46395,
    46397,
    46398,
    46399,
    46400,
    46402,
    46403,
    46404,
    46406,
    46409
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 4");
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
10.6 that is missing Update 4.  As such, it is affected by several
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4562");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00001.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.6 Update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4473");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.4.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 4)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.4.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
