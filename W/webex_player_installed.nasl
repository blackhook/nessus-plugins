#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58620);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Cisco WebEx ARF/WRF Player Installed");
  script_summary(english:"Checks registry/filesystem for ARF/WRF Players");

  script_set_attribute(attribute:"synopsis", value:"A video player is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Cisco WebEx ARF and/or WRF Player is/are installed on the remote
host.  ARF Player is used to watch recordings downloaded from WebEx.
WRF Player is used to watch self-created WebEx recordings."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.webex.com/play-webex-recording.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

##
# Sets the version associated with a product in the installs array
# @param display_name_key the DisplayName KB key
# @param product the product, WRF or ARF Player
##
function get_version(display_name_key, product)
{
  local_var version_key = display_name_key - 'DisplayName' + 'DisplayVersion';
  local_var version = get_kb_item(version_key);

  installs[product]['version'] = version;
}

app = 'WebEx ARF/WRF Player';

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\WebEx\Uninstall";
names = make_list('NBRPath', 'RecordPlaybackPath');
paths = get_values_from_key(handle:handle, key:key, entries:names);
RegCloseKey(handle:handle);

if (isnull(paths))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
else
  close_registry(close:FALSE);

installs = make_array();

foreach name (keys(paths))
{
  # the value pulled from the registry should be the absolute pathname of an exe file
  path = paths[name];
  ver = hotfix_get_fversion(path:path);

  # all we need is evidence that the file exists
  if (ver['error'] == HCF_OK || ver['error'] == HCF_NOVER)
  {
    # extract the directory from the pathname
    parts = split(path, sep:"\", keep:FALSE);
    dir = '';
    for (i = 0; i < max_index(parts) - 1; i++)
      dir += parts[i] + "\";

    if (name == 'NBRPath')
      installs['ARF Player'] = make_array('path', dir);
    else if (name == 'RecordPlaybackPath')
      installs['WRF Player'] = make_array('path', dir);
  }
}

hotfix_check_fversion_end();

if (max_index(keys(installs)) == 0)
  audit(AUDIT_UNINST, app);

port = kb_smb_transport();

# The DisplayName, while not always reliable, seems to be the only way to get the version in this case as the versions
# on other files don't correspond to the advisory version
wrf_display_name_key = hotfix_displayname_in_uninstall_key(pattern:'Webex Recorder and Player');
if (wrf_display_name_key)
    get_version(display_name_key:wrf_display_name_key, product:'WRF Player');

arf_display_name_key = hotfix_displayname_in_uninstall_key(pattern:'Network Recording Player');
if (arf_display_name_key)
    get_version(display_name_key:arf_display_name_key, product:'ARF Player');

# Register combined ARF/WRF for previously existing plugins
foreach product (keys(installs))
{
  path = installs[product]['path'];
  version = installs[product]['version'];
  set_kb_item(name:'SMB/' + product + '/path', value:path);
  extra = make_array('Product', 'Webex ' + product);

  register_install(
    app_name:app,
    vendor : 'Cisco',
    product : 'Webex',
    path:path,
    cpe:'cpe:/a:cisco:webex',
    version:version,
    extra:extra
  );
}

report_installs(app_name:app, port:port);

