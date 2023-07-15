#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(62042);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_name(english:"SMB QuickFixEngineering (QFE) Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has quick-fix engineering updates installed.");
  script_set_attribute(attribute:"description", value:
"By connecting to the host with the supplied credentials, this plugin
enumerates quick-fix engineering updates installed on the remote host
via the registry.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("spad_log_func.inc");

##
# converts a unix timestamp to a human readable date in YYYY/MM/dd format
#
# @anonparam unixtime unix timestamp
# @return human readable date if the conversion succeeded,
#         NULL otherwise
##
function unixtime_to_date()
{
  local_var unixtime, time, date, month, mday;
  unixtime = _FCT_ANON_ARGS[0];
  if (isnull(unixtime)) return NULL;

  time = localtime(unixtime);
  date = time['year'] + '/';

  month = int(time['mon']);
  if (month < 10)
    date += '0';
  date += time['mon'] + '/';

  mday = int(time['mday']);
  if (mday < 10)
    date += '0';
  date += time['mday'];

  return date;
}

port = kb_smb_transport();

get_kb_item_or_exit('SMB/Registry/Enumerated');
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

kbs = make_array(); # key - KB name, value - install date (empty string if a date is not available)
if (winver == '5.1' || winver == '5.2')
{
  spad_log(message:'Uninstall KBs Found:');
  display_names = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  install_dates = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/InstallDate");
  foreach key (keys(display_names))
  {
    if (key =~ 'Uninstall/(M|S|KB)[0-9]+((-|_)[A-Za-z0-9]+)?/DisplayName')
    {
      spad_log(message:' - '+key);
      key = key - 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/';
      key = key - '/DisplayName';
      if (isnull(kbs[key]))
      {
        spad_log(message:'  - :'+key);
        date = install_dates["SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/" + key + "/InstallDate"];
        if (isnull(date))
          kbs[key] = '';
        else
          kbs[key] = date;
      }
    }
  }
}
else
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages";
  subkeys = get_registry_subkeys(handle:hklm, key:key);

  spad_log(message:'CBS KBs Found:');

  foreach subkey (subkeys)
  {
    if (subkey =~ '(KB)?[0-9]+')
    {
      kb = ereg_replace(string:subkey, pattern:'.*((KB[0-9]+)(~|-|_)[A-Za-z0-9]+).*', replace:"\2");
      if (kb =~ '^KB[0-9]+((~|-|_)[A-Za-z0-9]+)?$')
      {
        if ('_client' >< kb) kb = kb - '_client';

        spad_log(message:' - '+subkey);
        spad_log(message:'  - '+kb);

        # try to determine the install date if possible
        if (isnull(kbs[kb]))
        {
          names = make_list('InstallTimeHigh', 'InstallTimeLow');
          values = get_values_from_key(handle:hklm, key:key + "\" + subkey, entries:names);
          hightime = values['InstallTimeHigh'];
          lowtime = values['InstallTimeLow'];

          date = '';
          if (!isnull(hightime) && !isnull(lowtime))
          {
            unixtime = convert_win64_time_to_unixtime(high:hightime, low:lowtime);
            date = unixtime_to_date(unixtime);
            if (isnull(date)) date = '';
          }
          kbs[kb] = date;
        }
      }
    }
  }

  RegCloseKey(handle:hklm);
}
close_registry();

if (max_index(keys(kbs)) > 1)
{
  qfes = '';
  foreach kb (keys(kbs))
  {
    if (qfes) qfes = qfes + ',' + kb;
    else qfes = kb;
  }
  set_kb_item(name:'SMB/Microsoft/qfes', value:qfes);
  report =
    '\nHere is a list of quick-fix engineering updates installed on the' +
    '\nremote system :\n';
  foreach kb (sort(keys(kbs)))
  {
    report = report + '\n' + kb;
    date = kbs[kb];
    if (date != '') report += ', Installed on: ' + date;
  }
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
else exit(0, 'No quick-fix engineering updates were found on the remote host.');
