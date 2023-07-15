#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(148541);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

 script_name(english:"Windows Language Settings Detection");

 script_set_attribute(attribute:"synopsis", value:"This plugin enumerates language files on a windows host.");
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, 
this plugin enumerates language IDs listed on the host.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');
include('lists.inc');
include('http.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var language_key_install = 'SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\InstallLanguage';
var language_key_default = 'SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\Default';
registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
var install_language = get_registry_value(handle:hklm, item:language_key_install);
var default_language = get_registry_value(handle:hklm, item:language_key_default);
RegCloseKey(handle:hklm);
close_registry(close:TRUE);

if (empty_or_null(install_language)) 
  install_language = "Not Detected";
else
{
  set_kb_item(name:language_key_install, value: install_language);
  install_language = hex2dec(xvalue:install_language);
  set_kb_item(name:'SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\InstallLanguage\\(DEC)', value: install_language);
}

if (empty_or_null(default_language))
  default_language = "Not Detected";
else
{
  set_kb_item(name:language_key_default, value: default_language);
  default_language = hex2dec(xvalue:default_language);
  set_kb_item(name:'SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\Default\\(DEC)', value: default_language);
}

var language_lists = 
  make_list(
  default_language,
  install_language,
  1033, #English - US
  1036, #French
  1044, #Norwegian
  1049, #Russian
  2047, #Serbian
  2052, #Simplified Chinese
  2058, #Spanish (Mexico) / Mostly Unused Halfway to legacy
  3082 #Spanish (Modern)
);

language_lists = collib::remove_duplicates(language_lists);

foreach(var language in language_lists)
	set_kb_item(name:"SMB/base_language_installs" , value:language);

report =
  'Default Install Language Code: ' + install_language + '\n' +
  '\n'+
  'Default Active Language Code: ' + default_language + '\n' +
  '\n' +
  'Other common microsoft Language packs may be scanned as well.'
;

security_note(extra:report);