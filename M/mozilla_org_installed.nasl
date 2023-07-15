#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20862);
  script_version("1.77");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_xref(name:"IAVT", value:"0001-T-0672");

  script_name(english:"Mozilla Foundation Application Detection");
  script_summary(english:"Checks for various applications from the Mozilla Foundation.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains one or more applications from the
Mozilla Foundation.");
  script_set_attribute(attribute:"description", value:
"There is at least one instance of Firefox, Thunderbird, SeaMonkey, or
the Mozilla browser installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:mozilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

function is_esr_release(app, app_install_path, ver)
{
  local_var fh, data, fsize, offset, path2, pattern, is_esr;
  local_var xul_path, firefox_xul_esr_tag_addrs, paths2;
  local_var thunderbird_xul_esr_tag_addrs, addrs, reads;
  local_var login, pass, domain, rc, share;

  is_esr = FALSE;

  # Addresses for one of a few strings :
  #   rel-m-esr
  #   BuildID{null}esr{null}
  #   c:\builds\moz2_slave\m-esr45-
  #   c:\builds\moz2_slave\m-esr52-
  # bgrep 72656c2d6d2d657372 xul.dll
  # bgrep 4275696c64494400657372 xul.dll
  # bgrep 633a5c6275696c64735c6d6f7a325f736c6176655c6d2d65737234352d77
  # bgrep 633a5c6275696c64735c6d6f7a325f736c6176655c6d2d65737235322d77
  # or xxd
  # These strings do not exist in non-ESR.
  firefox_xul_esr_tag_addrs = make_array(
    "10.0.0",   12318528,
    "10.0.1",   12318528,
    "10.0.2",   12314432,
    "10.0.3",   12322624,
    "10.0.4",   12318528,
    "10.0.5",   12314448,
    "10.0.6",   12326720,
    "10.0.7",   12326416,
    "10.0.8",   12330512,
    "10.0.9",   12326416,
    "10.0.10",  12330528,
    "10.0.11",  12334608,
    "10.0.12",  12339328,
    "17.0.0",   12326224,
    "17.0.1",   12334880,
    "17.0.2",   12345632,
    "17.0.3",   12352556, # BuildID.esr.
    "17.0.4",   12348468, # BuildID.esr.
    "17.0.5",   12344884, # BuildID.esr.
    "17.0.6",   12336180, # BuildID.esr.
    "17.0.7",   12352580, # BuildID.esr.
    "17.0.8",   12332108, # BuildID.esr.
    "17.0.9",   12334156, # BuildID.esr.
    "17.0.10",  12356612, # BuildID.esr.
    "17.0.11",  12355076, # BuildID.esr.
    "24.0.0",   15632528,
    "24.1.0",   15258672,
    "24.1.1",   15644288,
    "24.2.0",   15731104,
    "24.3.0",   15310752,
    "24.4.0",   15323232,
    "24.5.0",   15320176,
    "24.6.0",   15689504,
    "24.7.0",   15318720,
    "24.8.0",   15711664,
    "24.8.1",   15303952,
    "31.0.0",   17345248,
    "31.1.0",   17327792,
    "31.1.1",   17337120,
    "31.2.0",   17343616,
    "31.3.0",   17329952,
    "31.4.0",   17351317,
    "31.5.0",   17335413,
    "31.5.1",   17356029,
    "31.5.2",   17362301,
    "31.5.3",   17353981,
    "31.6.0",   17341781,
    "31.7.0",   17331549,
    "31.8.0",   17357437,
    "38.0.0",   26703789,
    "38.0.1",   27996077,
    "38.1.0",   26741173,
    "38.1.1",   26594821,
    "38.2",     26697877,
    "38.2.1",   26680109,
    "38.3.0",   28094597,
    "38.4.0",   27609629,
    "38.5.0",   26728701,
    "38.5.1",   26820968,
    "38.5.2",   26890893,
    "38.6.0",   26745741,
    "38.6.1",   26705597,
    "38.7.0",   26812477,
    "38.7.1",   26873461,
    "38.8.0",   28216453,
    "45.0",         30059549, # 32bit
    "45.0-64bit",   36300213, # 64bit
    "45.0.1",       30137997, # 32bit
    "45.0.1-64bit", 36838005, # 64bit
    "45.0.2",       30161797, # 32bit
    "45.0.2-64bit", 36564005, # 64bit
    "45.1.0",       29831445, # 32bit
    "45.1.0-64bit", 36365861, # 64bit
    "45.1.1",       29857440, # 32bit
    "45.1.1-64bit", 36521685, # 64bit
    "45.2.0",       30086248, # 32bit ; c:\builds\moz2_slave\m-esr45-
    "45.2.0-64bit", 36566064, # 64bit ; c:\builds\moz2_slave\m-esr45-
    "45.3.0",       31050120, # 32bit ; c:\builds\moz2_slave\m-esr45-
    "45.3.0-64bit", 36272896, # 64bit ; c:\builds\moz2_slave\m-esr45-
    "45.4.0",       31234360, # 32bit ; c:\builds\moz2_slave\m-esr45-
    "45.4.0-64bit", 36315072, # 64bit ; c:\builds\moz2_slave\m-esr45-
    "45.5.0",       30805232, # 32bit ; c:\builds\moz2_slave\m-esr45-
    "45.5.0-64bit", 35918928, # 64bit ; c:\builds\moz2_slave\m-esr45-
    "45.5.1",       30937552, # 32bit ; c:\builds\moz2_slave\m-esr45-
    "45.5.1-64bit", 36740368, # 64bit ; c:\builds\moz2_slave\m-esr45-
    "45.6.0",       30776488, # 32bit ; c:\builds\moz2_slave\m-esr45-
    "45.6.0-64bit", 36559248, # 64bit ; c:\builds\moz2_slave\m-esr45-
    "45.9.0",       30905696, # 32bit ; c:\builds\moz2_slave\m-esr45-
    "45.9.0-64bit", 36415248, # 64bit ; c:\builds\moz2_slave\m-esr45-
    "52.0",         31611016, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.0-64bit",   38796496, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.0.1",       31627752, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.0.1-64bit", 38676080, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.1",         31598776, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.1-64bit",   38435680, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.1.1",       31786368, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.1.1-64bit", 38427248, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.1.2",       31879792, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.1.2-64bit", 38436416, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.2.0",       31737368, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.2.0-64bit", 38615616, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.2.1",       31728904, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.2.1-64bit", 38533248, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.3.0",       31813768, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.3.0-64bit", 38730752, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.4.0",       31785032, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.4.0-64bit", 38610656, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.4.1",       31933320, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.4.1-64bit", 38950000, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.5.0",       31943096, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.5.0-64bit", 38809104, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.5.2",       32041400, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.5.2-64bit", 38747184, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.5.3",       31937520, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.5.3-64bit", 38870960, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.6.0",       31915800, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.6.0-64bit", 38685344,  # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.7.0",       31878984, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.7.0-64bit", 38905456, # 64bit ; c:\builds\moz2_slave\m-esr52-
    "52.7.1",       32050264, # 32bit ; c:\builds\moz2_slave\m-esr52-
    "52.7.1-64bit", 38723376  # 64bit ; c:\builds\moz2_slave\m-esr52-
  );
  # Addresses for one of four strings :
  # esr{null}BuildID
  # win32_build_esr
  # tb-rel-c-esr
  # tb-rel-comm-esr
  #
  # bgrep 657372004275696c644944 xul.dll
  # bgrep 77696e33325f6275696c645f657372 xul.dll
  # bgrep 74622d72656c2d632d657372 xul.dll
  # bgrep 74622d72656c2d636f6d6d2d657372 xul.dll
  # or xxd
  # These strings do not exist in non-ESR for the
  # most part - if they do, the versions are
  # NOT true ESR and are NOT mapped here.
  thunderbird_xul_esr_tag_addrs = make_array(
    "10.0",     11431932,
    "10.0.1",   11431932,
    "10.0.2",   11431932,
    "10.0.3",   11431932,
    "10.0.4",   11436028,
    "10.0.5",   11436037,
    "10.0.6",   11440141,
    "10.0.7",   11444245,
    "10.0.8",   11444245,
    "10.0.9",   11444245,
    "10.0.10",  11444245,
    "10.0.11",  11444245,
    "10.0.12",  11444229,
    "17.0",     11757821,
    "17.0.2",   11929672,
    "17.0.3",   11932792,
    "17.0.4",   11932792,
    "17.0.5",   11933816,
    "17.0.6",   11934320,
    "17.0.7",   11935344,
    "17.0.8",   11937376,
    "17.0.9",   11937896,
    "17.0.10",  11938912,
    "17.0.11",  11938912
  );

  if ("firefox" >< tolower(app)) addrs = firefox_xul_esr_tag_addrs;
  if ("thunder" >< tolower(app)) addrs = thunderbird_xul_esr_tag_addrs;

  # If no mapping into xul.dll, don't waste traffic trying.
  # Also, do _not_ replace this old-style code with a
  # new-style full-file-read. xul.dll is too large for that.
  if (!isnull(addrs[ver]) || !isnull(addrs[ver+'-64bit']))
  {
    share =  ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:app_install_path);
    xul_path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:app_install_path+"\xul.dll");
    port    =  kb_smb_transport();
    login   =  kb_smb_login();
    pass    =  kb_smb_password();
    domain  =  kb_smb_domain();

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);

    if (rc != 1)
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL, share);
    }

    fh = CreateFile(
      file:xul_path,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (!isnull(fh))
    {
      if (!isnull(addrs[ver]))
        offset = addrs[ver] - 100; # small pre buffer
      else
        offset = addrs[ver+'-64bit'] - 100; # small pre buffer

      data = ReadFile(handle:fh, length:200, offset:offset);
      if (
        # Firefox strings
        "rel-m-esr" >< data ||
        'BuildID'+raw_string(0x00)+'esr' >< data ||
        "c:\builds\moz2_slave\m-esr45-" >< data ||
        "c:\builds\moz2_slave\m-esr52-" >< data ||
        # Thunderbird strings
        'esr'+raw_string(0x00)+'BuildID' >< data ||
        'win32_build_esr' >< data ||
        'tb-rel-c-esr' >< data ||
        'tb-rel-comm-esr' >< data
      )
      {
        is_esr = TRUE;
      }
    }
  }
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (is_esr) return TRUE;

  # Try three fallback files.
  # These are text files and are susceptible
  # to admin/user tinkering, thus fallbacks.
  # Note that update-settings.ini contains
  # explicit instructions NOT to modify.
  paths2 = make_list(app_install_path+"\defaults\pref\channel-prefs.js");

  # application.ini is not reliable in Thunderbird,
  # e.g., version 31.1.1 application.ini contains :
  # SourceRepository=https://hg.mozilla.org/releases/comm-esr31
  #
  # update-settings.ini relates to FF >= 60.x
  if ("firefox" >< tolower(app))
  {
    paths2 = make_list(paths2, app_install_path+"\application.ini");
    paths2 = make_list(app_install_path+"\update-settings.ini", paths2);
  }

  foreach path2 (paths2)
  {
    var file = hotfix_get_file_contents(path:path2);

    if (!hotfix_handle_error(error_code:file['error'],file:path2,appname:app,exit_on_fail:FALSE))
    {
      data = file['data'];
      if
      (
        # channel-prefs.js file
        'pref("app.update.channel", "esr")' >< data
        ||
        # application.ini file
        'SourceRepository=https://hg.mozilla.org/releases/mozilla-esr' >< data
        ||
        # update-settings.ini file
        'ACCEPTED_MAR_CHANNEL_IDS=firefox-mozilla-esr' >< data
      )
      {
        is_esr = TRUE;
        break;
      }
    }
    else is_esr = "ERROR";
  }

  return is_esr;
}

##
# Inspects subkeys of a given SOFTWARE\Mozilla registry key to find Mozilla software installation paths.
# @param hive Either HKLM or HKU, depending on which hive is insepected - returned by registry_hive_connect().
# @param appended_subkey Optional string that should be appended as a prefix to each enumerated subkey - used for HKU subkeys.
# @param subkeys An array of subkeys coming from get_registry_subkeys() or get_hku_keys().
# @param exes A reference to the exe name:path array that should be populated by this function.
# @param lcexes A reference to the lowercase exe name:counter array that should be populated by this function.
# @return NULL - output is passed via references.
##
function enumerate_mozilla_key(hive, appended_subkey, subkeys, &exes, &lcexes)
{
  if (empty_or_null(subkeys)) return NULL;

  foreach var key (keys(subkeys))
  {
    foreach var subkey (subkeys[key])
    {
      if (subkey =~ "^(Mozilla|Mozilla Firefox|Mozilla Thunderbird|SeaMonkey) [0-9]+\.[0-9]+")
      {
        var key_prefix = key;
        if(!empty_or_null(appended_subkey)) key_prefix = local_detection_win::append_path(path:key, value:appended_subkey);

        var path_to_exe = key_prefix + "\" + subkey + "\bin\PathToExe";
        var file = get_registry_value(handle:hive, item:path_to_exe);
        if (!isnull(file) && !lcexes[tolower(file)])
        {
          exes[file] = subkey;
          lcexes[tolower(file)]++;
        }
      }
    }
  }
  # Older versions seem to store info only under here.
  # Currently these should all be pre x64
  var apps = make_list(
    "Mozilla",
    "Mozilla Firefox",
    "Mozilla Thunderbird",
    "SeaMonkey"
  );
  foreach var app (apps)
  {
    key = "SOFTWARE\mozilla.org\" + app + "\Main\PathToExe";
    file = get_registry_value(handle:hklm, item:key);
    if (!empty_or_null(file) && !lcexes[tolower(file)])
    {
      exes[file] = app + " " + subkey;
      lcexes[tolower(file)]++;
    }
  }
  return NULL;
}

# Connect to the appropriate share.
get_kb_item_or_exit("SMB/Registry/Enumerated");

registry_init();

# Look in various registry hives for application info.
var exes = make_array();
var lcexes = make_array();

var prod_key = "SOFTWARE\Mozilla";

var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
var hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
var subkeys = get_registry_subkeys(handle:hklm, key:prod_key, wow:TRUE);
var user_subkeys = get_hku_keys(key:prod_key, hku:hku);

enumerate_mozilla_key(hive:hklm, subkeys:subkeys, exes:exes, lcexes:lcexes);
RegCloseKey(handle:hklm);

enumerate_mozilla_key(hive:hku, appended_subkey:prod_key, subkeys:user_subkeys, exes:exes, lcexes:lcexes);
RegCloseKey(handle:hku);

close_registry(close:FALSE);

# Determine the version of each app from each executable itself.
var info = "";
var errors = make_list();

# ESR branches
var firefox_esr_major_versions_pattern = "^(10\.|17\.|24\.|31\.|38\.|45\.|52\.|60\.|68\.|78\.|91\.|102\.)";
# Thunderbird ESR was merged into the mainstream and is no more
var thunderbird_esr_major_versions_pattern = "^(10\.|17\.)";

foreach var exe (keys(exes))
{
  var prod, p_ver, f_ver, ver, f_version;
  # Set the product name for checks
  prod = exes[exe];
  prod = ereg_replace(pattern:"^(.+) [0-9]+\..*$", replace:"\1", string:prod);

  # Determine its version from the executable itself.
  p_ver = NULL;
  f_ver = NULL;
  ver = '';
  f_version = '';
  p_ver = hotfix_get_pversion(path: exe);
  f_ver = hotfix_get_fversion(path: exe);

  if (pregmatch(pattern:"\'[0-9]+.[0-9]+.[0-9]+\'", string:p_ver["value"])){
    var fix_ver = str_replace(string:p_ver["value"], find:"\", replace:"");
    var fixed_ver = str_replace(string:fix_ver, find:"'", replace:'');
  }
  if (!isnull(fixed_ver))    
    p_ver["value"] = fixed_ver;

  var p_error = hotfix_handle_error(error_code:p_ver['error'],file:exe,appname:prod,exit_on_fail:FALSE);
  if(p_error)
  {
    errors = make_list(errors, p_error);
    continue;
  }

  ver = join(sep:".", p_ver["value"]);
  if(!hotfix_handle_error(error_code:f_ver['error'],file:exe,appname:prod,exit_on_fail:FALSE))
    f_version = join(sep:".", f_ver["value"]);

  # hack - in some earlier versions of Firefox and Thunder bird, it
  # looks like they mistakenly swapped FileVersion and ProductVersion.
  # If the ProductVersion doesn't look right, go with FileVersion
  if (
    !empty_or_null(f_version) &&
    ("firefox" >< tolower(prod) || "thunderbird" >< tolower(prod)) &&
    preg(string:ver, pattern:'^[1-9].[1-9].[1-9].[0-9]+')
    ) ver = f_version;

  # SeaMonkey 2.3.2 (based on Firefox 6.0.1) reports itself as 2.3.1
  if ( "seamonkey" >< tolower(prod) && !empty_or_null(f_version) &&  f_version =~ "^6\.0\.1\." && ver == '2.3.1')
    ver = '2.3.2';


  var path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:exe);


  if ("firefox" >< tolower(prod))
    var esr_major_versions_pattern = firefox_esr_major_versions_pattern;
  if ("thunderbird" >< tolower(prod))
    esr_major_versions_pattern = thunderbird_esr_major_versions_pattern;

  if (!empty_or_null(f_version) && ver && ver =~ "^1\.[0-9]+.*\: 200[0-9]")
    ver = ver - strstr(ver, ":");

  var kb_base = str_replace(find:" ", replace:"/", string:prod);

  # Check if this is an ESR branch (before marking installs)
  var note = '';
  if ("firefox" >< tolower(prod) || "thunderbird" >< tolower(prod))
  {
    if (ver =~ esr_major_versions_pattern)
    {
      var is_esr = is_esr_release(app:prod, app_install_path:path, ver:ver);
      # Note that 'is_esr' can only be "ERROR", TRUE or FALSE
      if (is_esr == "ERROR")
      {
        errors = make_list(errors, "Unable to open file '"+exe+"'");
        continue;
      }
      if (is_esr)
      {
        set_kb_item(name:"SMB/"+kb_base+"/"+ver+'/is_esr', value:TRUE);
        prod += ' ESR';
      }
    }
  }

  save_version_in_kb(key:kb_base+"/Version", ver:ver);
  set_kb_item(name:"SMB/"+kb_base+"/"+ver, value:path);

  var fa_app_name = NULL;
  var product = NULL;
  var edition = NULL;
  var sw_edition = NULL;
  switch (prod)
  {
    case "Mozilla Firefox": 
      fa_app_name =  "Firefox";
      product = 'Firefox';
      break;
    case "Mozilla Firefox ESR": 
      fa_app_name = "Firefox ESR"; 
      product = "Firefox";
      sw_edition = "ESR";
      break;
    case "Mozilla Thunderbird": 
      fa_app_name = "Thunderbird"; 
      product = "Thunderbird";
      break;
    case "Mozilla Thunderbird ESR": 
      fa_app_name = "Thunderbird ESR"; 
      product = "Thunderbird";
      sw_edition = "ESR";
      break;
  }

  register_install(
    app_name:prod,
    vendor : 'Mozilla',
    product : product,
    sw_edition : sw_edition,
    path:path,
    version:ver,
    cpe:"cpe:/a:mozilla:mozilla",
    fa_app_name: fa_app_name);


  info += '\n  Product : ' + prod +
          '\n  Path    : ' + path +
          '\n  Version : ' + ver +
          '\n';
}

var port = kb_smb_transport();
var report, errmsg;
hotfix_check_fversion_end();

if (info)
{
  report = '\n' + info;
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
}
else
{
  if (max_index(errors))
  {
    if (max_index(errors) == 1) errmsg = errors[0];
    else errmsg = 'Errors were encountered verifying installs : \n  ' +
                  join(errors, sep:'\n  ');
    exit(1, errmsg);
  }
  else audit(AUDIT_NOT_INST, "Software from Mozilla.org");
}
