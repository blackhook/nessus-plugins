#TRUSTED 19da0b4288b2913f5589fb537310aac41d54936cc705fc7873d71d8ec8bd44cad5c343557ea065b73281bd7b743ffd1c6f22a0235ff34bf6872bf6b2e2dab732ca73575e4dfe5a19ebab4ee6b9627de0f6076408c39bf50f1c9c0ad16ea1a4102174fbd035e6574c55f2fb3776cdeb10d02291a583bbf86fedc334745be2f5c49d5893e06248bdd840ae7cea1c39a5ea062d3178895f05087189557326bc89b83e2a465fb690dadfe6fc697bf931aa58addbdc97c0d7d1b48ad70663519744d1b1d0032ef21974bc3cc495e99e95e6dbec0ef2fefcbd145391f68560f8d2e1230c5a7435a6e496e8538986b26c418f280951359ab487613da330358bea14112a7d6f7a0b0863c570586ac8946e6e6a82bcfb16b5390653b4354a8ff61b52d2ff6f83278b618f52b1cd467eff6bcb70077934a31279979105c107c4eb9a3b2a058d2e203e26305ab2e64351195aba0db95678447d7e45718d889ab03088b24dc0d7a911ae5c09df233ac464f97db13ea389d5e050574f5ffec81cf406d68784ecf704485301cf314c58301075fca349ddab386855e8f3ae7dd24e7694118e5ee635c5cba7081b627a3f14287d973b4d20ac1a1c409b175ff60264e6e22cc492d96b4439787e6ae2ff3ed4b0fd2dd7267b3299604bed66e1285a1d2e42eda3a647c77bc30abf74770d9a32bd7b4a9b915a6e82883f836b20c8159382854d0899cb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55417);
  script_version("1.38");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0510");

  script_name(english:"Firefox Installed (Mac OS X)");
  script_summary(english:"Gets the Firefox version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser.");
  script_set_attribute(attribute:"description", value:
"Mozilla Firefox is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
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

app = "Firefox";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

kb_base = "MacOSX/Firefox";

esr_ui = '';

path = '/Applications/Firefox.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, app);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, app);

# Check for ESR in versions < 60.x *before* saving anything
esr_major_versions_pattern = "^(10\.|17\.|24\.|31\.|38\.|45\.|52\.|60\.|68\.|78\.|91\.|102\.)";
if (version =~ esr_major_versions_pattern)
{
  xul_file = path + '/Contents/MacOS/XUL';
  cmd = 'grep -caie "esr.releasechannel\\|/builds/slave/\\(rel-\\)\\?m-esr[0-9]\\+-" '+xul_file;

  is_esr = exec_cmd(cmd:cmd);

  # is_esr will be any of :
  # 0 - not ESR, no matching lines
  # > 0 - ESR, more than zero matching lines
  # not an integer - ERROR of some sort
  if (strlen(is_esr))
  {
    if (is_esr =~ "[^0-9]") audit(AUDIT_FN_FAIL, "'"+cmd+"'", "a non-numeric value");

    is_esr = int(is_esr);

    if (is_esr > 0)
    {
      set_kb_item(name:kb_base+"/is_esr", value:TRUE);
      esr_ui = ' ESR';
    }
  }
  else audit(AUDIT_FN_FAIL, "'"+cmd+"'", "zero-length output");
}

# Check for ESR in versions >= 60.x *before* saving anything
var sw_edition = NULL;
if (version =~ esr_major_versions_pattern && empty_or_null(esr_ui))
{
  xul_file = path + '/Contents/Resources/update-settings.ini';
  cmd = 'grep -caie "ACCEPTED_MAR_CHANNEL_IDS=firefox-mozilla-esr" '+xul_file;

  is_esr = exec_cmd(cmd:cmd);

  # is_esr will be any of :
  # 0 - not ESR, no matching lines
  # > 0 - ESR, more than zero matching lines
  # not an integer - ERROR of some sort
  if (strlen(is_esr))
  {
    if (is_esr =~ "[^0-9]") audit(AUDIT_FN_FAIL, "'"+cmd+"'", "a non-numeric value");

    is_esr = int(is_esr);

    if (is_esr > 0)
    {
      set_kb_item(name:kb_base+"/is_esr", value:TRUE);
      esr_ui = ' ESR';
      sw_edition = 'ESR';
    }
  }
  else audit(AUDIT_FN_FAIL, "'"+cmd+"'", "zero-length output");
}

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:app + esr_ui,
  vendor : 'Mozilla',
  product : 'Firefox',
  sw_edition : sw_edition,
  path:path,
  version:version,
  cpe:"cpe:/a:mozilla:firefox");

report_installs(app_name:app + esr_ui);

