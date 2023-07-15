#TRUSTED 041fe73664ca6efe638dfe30bfa21226fdf17afb2919405a2b71ed69db51859a7bc5b8fe3e53732998193d4264f08a88c28d86a1aec8eae313ffd77bbdf269feea3379a87e1ff4d9b53cb6629fa4336e51c6b569ce0807130c9f773685c408e1ea033ed7d1e718e14a873899f3d8d25594860a16d31cc52584490d40ea50ac37206a8ecc1fdb8d7fd66fb53f08e49d69429a5c68bae72a80ec055b78075aba8d0cbba3202feac18e06555b5daa115a519e603949cd8b38008fe55d050081f3ea7725e7a8e35cef64f6071a5b8982c11ed70c31770bbbaed67659975bed10bd4aa9f1db29f1a0243b9de0052c5d75c2b91a1ea61ed8744af03dbf2b7ffff14b74e7911597a336e58383073572dc8bede455113970d196bbde624226b5de30da7b6115eca1676abe9e129939a37278c8390fb573148cdf27e4ba49c015954e6bab701ec2ad8c0b5312230e5efa00daae0539cb9c23fc23efb557ddd8c6e9f4e17cc484f8525a7aa78b2e7b80d583231ee81a24022218e76777e41ac1b1ab1416d9944ac5ca0f42458126213cefdd20a196bc038cbd9c04ae8841673c7fc11cd6997658a6f2a3cb726ea84e090e7d1ef8be0bd4617d70df910fd488def8c19b49c02238cd91708298eafb037c4ebcda476b3f8df9de99e7cb254ab0776c721eb3075e79679fb75f091a902e26691a832872c0ff603f0b517e8b65bea5a088441b42
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62909);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2012-1885",
    "CVE-2012-1886",
    "CVE-2012-1887",
    "CVE-2012-2543"
  );
  script_bugtraq_id(56425, 56426, 56430, 56431);
  script_xref(name:"MSFT", value:"MS12-076");
  script_xref(name:"MSKB", value:"2764047");
  script_xref(name:"MSKB", value:"2764048");

  script_name(english:"MS12-076: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2720184) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - A heap-based buffer overflow vulnerability exists due to
    the way the application handles memory when opening
    Excel files. (CVE-2012-1885)

  - A memory corruption vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1886)

  - A use-after-free vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1887)

  - A stack-based buffer overflow vulnerability exists due
    to the way the application handles data structures while
    parsing Excel files. (CVE-2012-2543)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-076");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011 and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
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


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
path = '/Applications/Microsoft Office 2011';
plist = path + '/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist';
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '14.2.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Office 2008 for Mac';
path = '/Applications/Microsoft Office 2008';
plist = path + '/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist';
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '12.3.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office 2008 for Mac / Office for Mac 2011 is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
