#TRUSTED 583a6727b0322e2a69e6d339e08b4e2839222c44e01552e94bf3ffc1aa3f197e052e29b1cc9af0e219b757f945d2423e2265e159cef9fdf5f6dcf39d0cd42226fe7a2e900f5a2bbf269627d11f78286dbc8130fcedde09dc0b207b6b490fa073b87102aa1d605ff0ef1c1f8f8e435b3f5a78c47bc57a8b1476035aa13f8e2528b3b12745b1f984af1a0b94de91a7d7100ca9dbe9195d750b94ce67a13a08831963e2dd121b999f6a633210043ade0195f2d95859f717422a788bdf90d20f878e748f944053893dfa0f8a1dbe86c510cf8598980d4db0f0357443c5b04417e03647fb9f574e3d08a95d4964c08968d64cdc5c9d493b32e7eb372513c2ef813a7ba776d53f8369f906d7643f8b33971da1a31226c94838d7a8d57fc0067443f7f7ce467b940d96f431b7ef6d3db72a0c7d2bca46b5ec0c5d9820b489f12a4e671b25dc4fdc384cd1cb6c8cf06c803d7243ec4978251c4ce77f9a5957b6e55d80fbb181a26d284f586eee284870e90f7d97e4832e2213dd48566b0a694a49fb55da6c8a68175b3477ee0c864b58034bbf6bc38edac686ff7430c2cc79f02ce18f067a003e4143d29be368e37ecfaf6794ec039222cc1e284fe0a6ceb9796baed1247136b1616d0623dda8276e8fd56d2a8df7d3c9dca622da7022c5855374c133e82997e99c7071ae6c43942468f009e64f565af9970d0a0d815f34428ad6bb9b11
#TRUST-RSA-SHA256 60fa545cdb28a6f501dfc9d2f031bf6b05f42a02842f8e73931518ce50fa52fe8c265092566c7d71895823f6520ac8161b0d4a01ec16d31060d182da68e7749f6dc44d4efbe7b32f97d653ecb1902ee8d1fe8e1fff47bae182e7991665f1124bc0f54cf322eb7c8ea6ce3d2c2819a5cf4d7ca84205dcaea2003ccef453d76e18f64cdd211c270a58ee538f35cf4e1bb8e73530bbee77c2d025f2344cf606d75677cb638504167f694c3334af49bc76ac36efe4936e9a7c1526137ba64a6e00aad426b5df4c62f875d6c10f821673389955da2b68e4abc04f5b6257a051f9ab9370104836afb59cb251ba0cc7097af3fad4475a9e01d8c5933f2bf1cd3323029eb1920f00368bd1a0fb0187f0ebc983239e3417dd93d86fdc042c804478f4027e014f2b9a52dde400fc0a85275bceb8d24574cbce173779cfa9410fbb2ac4b25bdbd17fd87ba1a60b655fa9fe93b83c089aca33362f91b6a83ed053e85c1dee2e56ce02fedc1a7924d32abf47fa3438b86cb52141cd7bbef2fcda7ae035dc566a077e74d78f07dd76792ff885672e6d707c3354b350f7b5b03d10bb58ed9fd441128b0cf72be1cae15413f15d41230f4294d094f5747ffa0b348788a38b98dafee08c4fd1bdffb5969131e98c2eb26901043c80f9c9d8e37c65219692867bb4bc376dd0687e9d6a4d796608d913c64322202da98914955b2b5d569ac8a7b76c21
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56567);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Mac OS X XProtect Detection");
  script_summary(english:"Checks for Apple's XProtect");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mac OS X host has an antivirus application installed on
it."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Mac OS X host includes XProtect, an antivirus / anti-
malware application from Apple included with recent releases of Snow
Leopard (10.6) and later.  It is used to scan files that have been
downloaded from the Internet by browsers and other tools. 

Note that this plugin only gathers information about the application
and does not, by itself, perform any security checks or issue a
report."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://en.wikipedia.org/wiki/Xprotect"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:apple:xprotect");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("debug.inc");
include("install_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("security_controls.inc");
include("spad_log_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

# Mac OS X 10.6 and 10.7.
var os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (preg(pattern:"Mac OS X ([0-9]\.|10\.[0-5]([^0-9]|$))", string:os))
  exit(0, "The host is running "+os+", which does not have XProtect.");

var os_ver = pregmatch(pattern:"Mac OS X (([0-9]+)\.([0-9]+)?)", string:os);

if (empty_or_null(os_ver) || empty_or_null(os_ver[2]))
  exit(0, "Unable to determine Mac OS X version.");

# Runs various comments to check XProtect's status.
#
var cmd1, cmd2, cmd3, cmd4, cmd5, plist1, plist4;

# - Is it configured to get updates?
plist1 = "/System/Library/LaunchDaemons/com.apple.xprotectupdater.plist";
cmd1 = 'cat \'' + plist1 + '\'';

# - Does the XProtectUpdater daemon exist?
cmd2 = 'ls -al /usr/libexec/XProtectUpdater';

# - Is the XProtectUpdater daemon loaded?
if (os_ver[2] == 10 && os_ver[3] < 8)
  cmd3 = 'launchctl list';
else
  cmd3 = 'spctl --status';

# - When was it last updated?
if (os_ver[2] > 10)
{
  cmd4 = "ls -l /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist";
}
else if (os_ver[2] == 10 && os_ver[3] < 14)    # 10.11 - 10.13
{
  cmd4 = "ls -l /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist";
}
else
{
  plist4 = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist";
  cmd4 = 
    'cat \'' + plist4 + '\' | ' +
    'grep -A 1 LastModification | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';
}

# - And what's its version?
#   (obtained different ways, depending on OS version)
if (os_ver[2] == 10 && os_ver[3] < 10)    # 10.6 - 10.7
  cmd5 = 'cat \'' + plist4 + '\' | grep -A 1 Version | tail -n 1 | sed \'s/.*<integer>\\([0-9]*\\)<\\/integer>.*/\\1/g\'';
else if (os_ver[2] == 10 && os_ver[3] == 10)    # 10.10
  cmd5 = 'defaults read /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist Version';
else if (os_ver[2] == 10 && os_ver[3] > 10 && os_ver[3] < 14)    # 10.11 - 10.13
  cmd5 = 'defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist';
else if ((os_ver[2] == 10 && os_ver[3] > 13) || (os_ver[2] > 10))   # 10.14+
  cmd5 = 'system_profiler SPInstallHistoryDataType | grep -A 5 "XProtectPlistConfigData"';

var results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3, cmd4, cmd5));
  dbg::detailed_log(lvl:2, msg:'cmd results: ' + obj_rep(results));

if (isnull(results)) exit(1, "Unable to determine the status of XProtect.");

var running = "unknown";
var sig_autoupdate = "unknown";
var kb_base = 'MacOSX/XProtect/';
if (os_ver[2] == 10 && os_ver[3] < 8)    # 10.7 or earlier
{
  if (isnull(results[cmd3]) || !egrep(pattern:"^1[ \t]+.+launchd", string:results[cmd3]))
    exit(1, "'launchctl list' failed, perhaps because it was run as a non-root user.");

  if (
    !isnull(results[cmd1]) && 
    egrep(pattern:"^[ \t]*<string>/usr/libexec/XProtectUpdater</string>", string:results[cmd1]) && 
    egrep(pattern:"^[ \t]*<key>RunAtLoad</key>", string:results[cmd1])
  )
  {
    set_kb_item(name:kb_base+'XProtectUpdater/Configured', value:TRUE);
    running = "yes";
  }
  else
  {
    set_kb_item(name:kb_base+'XProtectUpdater/Configured', value:FALSE);
    running = "no";
  }
}
else   # 10.8 or later (GateKeeper was introduced in 10.8)
{
  if (!isnull(results[cmd3]))
  {
    set_kb_item(name:kb_base+'spctl --status', value:results[cmd3]);
    if (results[cmd3] =~ "enabled")
    {
      running = "yes";
      sig_autoupdate = "yes";
    }
    else
    {
      running = "no";
      sig_autoupdate = "no";
    }
  }
}

set_kb_item(name:"Antivirus/XProtect/installed", value:TRUE);

if (
  !isnull(results[cmd2]) &&
  # nb: we're looking here for a file of a non-trivial size.
  egrep(pattern:"^.+rwx.+ root +wheel +[1-9][0-9]+ .+ /", string:results[cmd2])
)
{
  set_kb_item(name:kb_base+'XProtectUpdater/Exists', value:TRUE);
  sig_autoupdate = 'yes';
}

if (
  !isnull(results[cmd3]) && 
  "com.apple.xprotectupdater" >< results[cmd3]
) set_kb_item(name:kb_base+'XProtectUpdater/Loaded', value:TRUE);

if (!isnull(results[cmd4]))
{
  # might be date, or 'ls -l' output.
  if ("rw" >< results[cmd4])
  {
    var parts = split(results[cmd4], sep:' ', keep:FALSE);
    var sig_install_date;

    if ("Jan" >< parts[8])
      sig_install_date = parts[11] + "-01-" + parts[9];
    else if ("Feb" >< parts[8])
      sig_install_date = parts[11] + "-02-" + parts[9];
    else if ("Mar" >< parts[8])
      sig_install_date = parts[11] + "-03-" + parts[9];
    else if ("Apr" >< parts[8])
      sig_install_date = parts[11] + "-04-" + parts[9];
    else if ("May" >< parts[8])
      sig_install_date = parts[11] + "-05-" + parts[9];
    else if ("Jun" >< parts[8])
      sig_install_date = parts[11] + "-06-" + parts[9];
    else if ("Jul" >< parts[8])
      sig_install_date = parts[11] + "-07-" + parts[9];
    else if ("Aug" >< parts[8])
      sig_install_date = parts[11] + "-08-" + parts[9];
    else if ("Sep" >< parts[8])
      sig_install_date = parts[11] + "-09-" + parts[9];
    else if ("Oct" >< parts[8])
      sig_install_date = parts[11] + "-10-" + parts[9];
    else if ("Nov" >< parts[8])
      sig_install_date = parts[11] + "-11-" + parts[9];
    else if ("Dec" >< parts[8])
      sig_install_date = parts[11] + "-12-" + parts[9];

    set_kb_item(name:kb_base+'LastModification', value:sig_install_date);
  }
  else
  {
    set_kb_item(name:kb_base+'LastModification', value:results[cmd4]);
    sig_install_date = results[cmd4];
  }
}

var version, greatest_ver, sysprof_lines, line, date_parts; 
if (!isnull(results[cmd5]))
{
  # If version 10 and minor version is less than 10
  if (os_ver[2] == 10 && os_ver[3] < 10)   # 10.6 - 10.7
  {
    set_kb_item(name:kb_base+'DefinitionsVersion', value:results[cmd5]);
    version = results[cmd5];
  }
  else    # 10.10 or greater
  {
    version = UNKNOWN_VER;
    greatest_ver = NULL;
    if (!isnull(results[cmd5]))
    {
      if ('XProtectPlistConfigData' >< results[cmd5])
      {
        sysprof_lines = split(results[cmd5], sep:'XProtectPlistConfigData', keep:FALSE);
        foreach line (sysprof_lines)
        {
          if (line =~ "Version" && line =~ "Install Date")
          {
            version = pregmatch(string:line, pattern:'Version: (\\d+)');
            if (!empty_or_null(version) && !empty_or_null(version[1]))
            {
              if (isnull(greatest_ver) || int(version[1]) > greatest_ver)
              {
                greatest_ver = version[1];
                sig_install_date = pregmatch(string:line, pattern:'Install Date: ([^,]+),');
                if (!empty_or_null(sig_install_date) && !empty_or_null(sig_install_date[1]))
                {
                  sig_install_date = sig_install_date[1];
                  spad_log(message:'found greatest_ver ' + version[1] + ' and sig_install_date ' + sig_install_date + ' via line ' + line);
                }
              }
            }
          }
          else if(line =~ "CatalinaAndBigSur_" && line =~ "Install Date")
          {
            version = pregmatch(string:line, pattern:'CatalinaAndBigSur_(\\d+)');
            if (!empty_or_null(version) && !empty_or_null(version[1]))
            {
              if (isnull(greatest_ver) || int(version[1]) > greatest_ver)
              {
                greatest_ver = version[1];
                sig_install_date = pregmatch(string:line, pattern:'Install Date: ([^,]+),');
                if (!empty_or_null(sig_install_date) && !empty_or_null(sig_install_date[1]))
                {
                  sig_install_date = sig_install_date[1];
                  spad_log(message:'found greatest_ver ' + version[1] + ' and sig_install_date ' + sig_install_date + ' via line ' + line);
                }
              }
            }
          }
        }
        if (!isnull(greatest_ver))
        {
          version = greatest_ver;
          set_kb_item(name:kb_base+'DefinitionsVersion', value:version);
          date_parts = split(sig_install_date, sep:'/', keep:FALSE);
          if (!empty_or_null(date_parts) && !empty_or_null(date_parts[2]))
          {
            sig_install_date = "20" + date_parts[2] + "-";
            if (len(date_parts[0]) == 1)
              sig_install_date += "0" + date_parts[0] + "-";
            else
              sig_install_date += date_parts[0] + "-";
            if (len(date_parts[1]) == 1)
              sig_install_date += "0" + date_parts[1];
            else
              sig_install_date += date_parts[1];
          }

          set_kb_item(name:kb_base+'LastModification', value:sig_install_date);
        }
      }
      else if ('ExtensionBlacklist =' >< results[cmd5])
      {
        version = pregmatch(string:results[cmd5], pattern:"\n\s+Version = (\d\d\d\d)\;\n");
        if (!empty_or_null(version) && !empty_or_null(version[1]))
        {
          version = version[1];
          set_kb_item(name:kb_base+'DefinitionsVersion', value:version);
        }
        else
          spad_log(message:'Error: Unable to parse xprotect version from response "' + obj_rep(results[cmd5]) + '"');
      }
    }
  }
}  

var path = NULL;
var cpe = 'x-cpe:/a:apple:xprotect';

if (os_ver[2] == 10)
  path = "/System/Library/CoreServices/XProtect.bundle";
else
  path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle";


register_install(
  vendor:"Apple",
  product:"Xprotect",
  app_name: "Apple XProtect",
  path:path,
  version:version,
  cpe:cpe);


security_controls::endpoint::register(
  subtype                : 'EDR',
  vendor                 : 'Apple',
  product                : 'XProtect',
  product_version        : version,
  cpe                    : cpe,
  path                   : path,
  running                : running,
  signature_version      : version,
  signature_install_date : sig_install_date,
  signature_autoupdate   : sig_autoupdate
);

report_installs(app_name:"Apple XProtect");
