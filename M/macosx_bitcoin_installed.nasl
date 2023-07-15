#TRUSTED 4abb1cc55ed19c0876774de5791b8ce99d3210b5c6ec46209ab8bbb64fa924910ef5e3dd03f5480d10a828f60032cfad28de90ecae58301c297a2e159b7193614cc8314ffc0980971f2e4a72efda7a1f233573427cb2e4e25d0133dfc36dfd821aff04c618dc6e5ac9249514c35a99069dda164b81745c53a6a1fa8c7ccdd00927b01bb925a4a26d75290bc50345601114f359ae8d319bfd361bc8ffee79d92b0213d13a8bbc4bf950a6a26269f74ba55f11a0c6e77dacc13b0c83f7cef31f862ac020b628f592a884c55e07a33b78daf74b90dd66a00d53ea02934b89d2020df42dd1fb753d27d5f34adda1b97460581cc892e4e0d187692f287628c2122886cf493fbdfc6d3d52f5858809ec9b76012f28fb43383bf4dfc85ecf1d5b9090c7594dc0516490c4bae223e36255b4d6f84dbbf4e45538a2e66e70074cb12a48d582f0484b6d491322a555b1c99e6fc1d92c50bc31f19e2a432e69576b71b67281086f9b2717bf63673d107be756bcd4d7919396831d5ddc3e639103ef5614a5898e26a221e39bbda6f706dc1dfaa73d766dc53d98e11034838be35e3e31270bfac414ea9da3cfdca097674f2b7c686284aa2373cb4b8f91f76e1bb627761bde2603de61af04296d74aa76d2bb26354020f870c7f2ab768f4b2732549be8341c6c0d7b5c336239bc1bd6dc0c6484248dbf0876047e076a2d3573583ccb64f5a683
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56196);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Bitcoin Installed (Mac OS X)");
  script_summary(english:"Gets Bitcoin version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a digital currency application.");
  script_set_attribute(attribute:"description", value:
"Bitcoin is installed on the remote Mac OS X host. It is an open
source, peer-to-peer digital currency.");
  script_set_attribute(attribute:"see_also", value:"http://www.bitcoin.org/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitcoincore:bitcoin_core");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

app = "Bitcoin";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Bitcoin";


# Identify possible installs.
#
# - look under "/Applications".
paths = make_list("/Applications/Bitcoin.app");

# - look for running processes.
cmd = 'ps -o command -ax';
ps = exec_cmd(cmd:cmd);

if (strlen(ps))
{
  foreach line (split(ps, keep:FALSE))
  {
    match = eregmatch(pattern:"^([^ ]+/Bitcoin\.app)/Contents/MacOS/bitcoin", string:line);
    if (match)
    {
      path = match[1];
      # nb: ignore instances under "/Applications".
      if ("/Applications/Bitcoin.app" >!< path) paths = make_list(paths, path);
    }
  }
}


# And now the actual installs.
install_count = 0;

foreach path (paths)
{
  plist = path + '/Contents/Info.plist';
  cmd = 'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);

  if (strlen(version))
  {
    if (version !~ "^[0-9]") exit(1, "The Bitcoin version under '"+path+"' does not look valid (" + version + ").");

    set_kb_item(name:kb_base+"/"+path, value:version);

    register_install(
      app_name:app,
      vendor : 'Bitcoincore',
      product : 'Bitcoin Core',
      path:path,
      version:version,
      cpe:"cpe:/a:bitcoincore:bitcoin_core"
    );

    install_count += 1;
  }
}

if (!install_count) exit(0, "Bitcoin is not installed or running.");


# Report findings.
set_kb_item(name:kb_base+"/Installed", value:TRUE);
report_installs(app_name:app);

