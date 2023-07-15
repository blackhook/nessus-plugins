#TRUSTED 14d812c771c38631f67e468943ebd6a79c37273aee298dd97217e73e6c3bd48ea66efb72f2b8b25d369e5c2279b3600fc72882c1f3672548325c7ab7f5c13454adb9af507e0937f0bc55a0779a1f9c68aefa1dbd3bc2bc8031f225623d778d2f2ee7766dfdca505348c9b2fd4e179361eb9d27d6c2fef6ebca951c832434d4e66bd9a79087e1064bb7e7fedefa19c89d3a7139290cfeb5ff78b7b41bc1041dad4145d979b605143c8925c71f653e354df327459ba7f56af7cb22d61b10065d7da09b8247210d201ec1cec7821ca7a1c8c9a1d2427d0cfb0edcdeecef8e81581979b63aa10b49afad2364233c9cf39c2f2efc1dfd743d9aeb213b5f4574d9197c82b6a0cb2e9ff90e3c284c8b8e9e182da881b6f693825e38602f34f0b1d832d096e4b7e6e30f894d8312f40ffa84ecca263d9ee68ca6e0938ec161963c9478f275db3d45886722ca39904f8c7854a561c7894d108c0feafdf123ec33284a8fe18cedcbc6371664ac108195c2a330de92354e54ea1ff343862d58e44323868edd7ceaf69d0faa05df2220a2586cf7f94e09fed223768cf95915d88a5e1ae5c4392591b830ab2e951abcecdebb194e0bb837a07016b7fd9d39958e485b94e2604782b7e4e76b86ce54e09523dea444726fe2d1edaab7a31941f0b494dda62d2899911b54fffcf8058a1a0b2a949d97292ae734d98d273136a4e81efab336b814d2
#TRUST-RSA-SHA256 6e79208805e7dc74e166b725c9624c6215ebb5efd31f427c6d54ad9d908a227a9d7b55ead2608c69676422cb9e6e80cfcce8fac8c610cb20789ef95efb7b16b4f063c8318597020ee5bfdcbacfd229cd3c56c25f09a8201c296ae95e79b3e7bbadd6a93d2826509f9a5d83aec8b83f40cf631f13ffa63c11028790a0df69699c4dcfed10b153a243eba2b1fd33a1b8da6c03852ae689860e2367290bbd589ee6b41e1639f5f8fe7b2a3e806dedb0c7d49a6944dc8e6d90b30fd041e0bf2be9538b9a0cc6b6ad217aaee9bb81d603012f38123c75b47b035ef555d46f93a791ff62aa605b1df702cec90b44d6e9aa0c45c1f4d35b876861506b70dd977574d16cfb948c1f1c660b9f84a75e0e6fad8e842ac7bd229f1412721998c35a3fd9d6f8af41dab699e9657aaee2ea903ba1bf2d8c077a9b06655c2ced2810d8399e4c863dd6c35afcad3e79f757c4f3c7397339bb2023bab29e7b655445e6e85660c2d3c4c2e9a61302497709b8925b6da77cac824fb071923ac807d376c7e43c715d5063ea03aa2cafe3437a35cec0e739caabf4dd58df92237840c640cdc429be9735d6298e62548d3f4cc22328d7e50a6d3e14178e05a5113bfd67ebfd3b3331130ee57e3b5f86e59ad831e07f18f95b6f8e1d8f0949a8f6022d2a76858bfa02762a3d7872916205ae077e786b6f2581f3dad4d11690e908c823e92f539a687a33c5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52587);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 9");
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
10.5 that is missing Update 9.  As such, it is affected by several
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4563");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 Update 9 or later.");
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


# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

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

# Fixed in version 12.8.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 8)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.8.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
