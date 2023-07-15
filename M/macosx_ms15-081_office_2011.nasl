#TRUSTED 6f7ad7044c5fffe4e7948ed06265209abad9a726bde6872862f458b17a32b6d1a1aff3290e6ceb1080005510c588c7ead0dac1860311fd265e2d4943bde03fc9cfefa9fc29f69f3bc838dbb63e4ea0f15e514d59dfbb221d89e1be17418e0e90b5fbc2e40c4cfcc28dd8d65f220e5362ab8a05a935f132fa9c69181433400ec7db85250b9053ec0cb132c998efcac562b78eb922a64dda6ae5920600a51d1f17347b425aeea3ca3f513d216db8e4df3c459777dcd0f16861ad74cd03e49021818f111ee5e1d1f851f56f7f96cb5dae49b916c62eccd57c75e25e0aef00164ef216fa9b31db6a7067c66f72631d971e3d35f92321bed2ead3efaf7e0caefb8c8e2b66408b6e028ed86fe583ee0cb2265287daedff39dfe3187c1a3cd4af804c7cb3d0aa3bc3f67f0640801d19df95ec6ee7e7486cdb54e065f06536385e6b5a645652ee532c294fab8c8231f41972535b031960b0e1bd7c845ba4b1700336f4f67b3cedb6dbc8392dc29fd05d62003b89eb96414c531aa94ce162b61ce6ac6d35805566722773fedabb9254d9dd8e7fdf6620083fa02313bfd5b08986b93e7d969861bb1636591c584164050c9225735a5b95f2e10945dc53b49c1f1fbe3f67f51d38d4b244aa5355938872bc6e0976aa17acec45e400dbd0ef5ae604a01a9866b0c1d8e5ab94bbd151d2d45625e2ae67c85b9d9e63dc6bad1e40386d8b527ce4
#TRUST-RSA-SHA256 81cb39596ddea6578afd8cdffe67814d040c63785ac47b016d10fdfbc1c3271caca9530b8e54dde3f3ab2748c3ca10d6e187140ddef743d9745fbb554128a9a1bbee141c3b67f485c97adaf8956e609bc23b4dccd5fff87569384f0f3b5133ad8a0a42132ecfd054e0eb4abb4fb304317e8e7f12be7e59d213a2f397654dc7bd780d32af33ee07b0310d615957626f4f0a75b44595c45938dc95d1f4213926779a3afdf696868736807ef75bcd95d660cf65e0720d22fa8919ceeed1014e7af88a59000f8a376227698ffb6a1689871361b325a84d16918639bf37eada878a4f4410221a7c1191a4f3a8f4f171d74aa805cb00fb779b11a7a812deafa395fe2d494f0683431e391ad128a0d836d86cb22c0656965b91083409562b680546aa1eb74978e33e6a6e9d0d785b2c741eb1061465910479192aa4bb3b103f18537902a56315a0a2209f3a6607e265b4d22814b9fcd5d3f3cc6b7aa2cae63057bcf6dd3a15bfd8574e7f473d233235564fa449c1504513219ecf334b29cb19bdc55ea8106221e667cf69f40f69e6f3e9e9f49a0d1ccdba9eca54abd2322171ea4767ac3f7266b2c6a4470df21074f2e66d7820f65aab74899cf068001a2028f3f637c4cf500b697e5cab639c195bb9d6587867694894e73217c8420873a48959ef506f9f41e27cb5449271d258186f379f0c537e1f568f9e6708e1b0215d0dd91ea62e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85349);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2015-2468",
    "CVE-2015-2469",
    "CVE-2015-2470",
    "CVE-2015-2477"
  );
  script_bugtraq_id(
    76206,
    76212,
    76214,
    76219
  );
  script_xref(name:"MSFT", value:"MS15-081");
  script_xref(name:"IAVA", value:"2015-A-0194-S");
  script_xref(name:"MSKB", value:"3081349");

  script_name(english:"MS15-081: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3072620) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office installed
that is affected by multiple remote code execution vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted Office file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-2468,
    CVE-2015-2469, CVE-2015-2477)

  - A remote code execution vulnerability exists when Office
    decreases an integer value beyond its intended minimum
    value. A remote attacker can exploit this vulnerability
    by convincing a user to open a specially crafted Office
    file, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2015-2470)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-081");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2016:mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
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

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.5.4';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
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
