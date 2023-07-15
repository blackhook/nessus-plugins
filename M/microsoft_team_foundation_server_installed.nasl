#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(62033);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_xref(name:"IAVT", value:"0001-T-0669");

  script_name(english:"Microsoft Visual Studio Team Foundation Server / Azure DevOps Server Detection (credentialed check)");
  script_summary(english:"Checks for a Microsoft Visual Studio Team Foundation Server or Azure DevOps Server install");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a suite of tools for collaborative software
development."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Microsoft Visual Studio Team Foundation
Server or Azure DevOps Server. This software is a suite of tools for
collaborative software development."
);
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# List of arrays, because indexed
# adding reference: https://learn.microsoft.com/en-us/azure/devops/release-notes/features-timeline-released
var update_vers = { "^10\.":[ {'ver' : '10.0.30319.1',   'update' : '0',   'name' : 'RTM'},
                          {'ver' : '10.0.40219.1',   'update' : '1',   'name' : 'SP1'},
                          {'ver' : '10.0.40219.371', 'update' : '1.2', 'name' : 'SP1 Cumulative Update 2'}
                        ],
                "^11\.":[ {'ver' : '11.0.50727.1',   'update' : '0',   'name' : 'RTW'},
                          {'ver' : '11.0.51106.1',   'update' : '1',   'name' : 'Update 1'},
                          {'ver' : '11.0.60123.100', 'update' : '1.1', 'name' : 'Update 1 Cumulative Update 1'},
                          {'ver' : '11.0.60315.1',   'update' : '2',   'name' : 'Update 2'},
                          {'ver' : '11.0.60610.1',   'update' : '3',   'name' : 'Update 3'},
                          {'ver' : '11.0.61030.0',   'update' : '4',   'name' : 'Update 4'}
                        ],
                "^12\.":[ {'ver' : '12.0.21005.1',   'update' : '0',   'name' : 'RTM'},
                          # No update 1 was released
                          {'ver' : '12.0.30324.0',   'update' : '2',   'name' : 'Update 2'},
                          {'ver' : '12.0.30723.0',   'update' : '3',   'name' : 'Update 3'},
                          {'ver' : '12.0.31101.0',   'update' : '4',   'name' : 'Update 4'},
                          {'ver' : '12.0.40629.0',   'update' : '5',   'name' : 'Update 5'}
                        ],
                "^14\.":[ {'ver' : '14.0.23128.00',   'update' : '0',   'name' : 'RTM'},
                          {'ver' : '14.0.24720.00',   'update' : '1',   'name' : 'Update 1'},
                          {'ver' : '14.95.25122.00',  'update' : '2',   'name' : 'Update 2'},
                          {'ver' : '14.102.25423.00', 'update' : '3',   'name' : 'Update 3'},
                          {'ver' : '14.114.26403.0',  'update' : '4',   'name' : 'Update 4'},
                          {'ver' : '14.114.26412.0',  'update' : '4.1', 'name' : 'Update 4.1'},
                          {'ver' : '14.114.28829.0',  'update' : '4.2', 'name' : 'Update 4.2'}
                        ],
                "^15\.":[ {'ver' : '15.105.25910.0',  'update' : '0',   'name' : 'RTM'},
                          {'ver' : '15.105.27412.0',  'update' : '0.1', 'name' : 'Update 0.1'},
                          {'ver' : '15.112.26301.0',  'update' : '1',   'name' : 'Update 1'},
                          {'ver' : '15.117.26714.0',  'update' : '2',   'name' : 'Update 2'},
                          {'ver' : '15.117.27024.0',  'update' : '3',   'name' : 'Update 3'},
                          {'ver' : '15.117.27414.0',  'update' : '3.1', 'name' : 'Update 3.1'}
                        ],
                "^16\.":[ {'ver' : '16.122.27102.1',  'update' : '0',   'name' : 'RTW'},
                          {'ver' : '16.122.27409.2',  'update' : '1',   'name' : 'Update 1'},
                          {'ver' : '16.122.28028.4',  'update' : '1.1', 'name' : 'Update 1.1'},
                          {'ver' : '16.122.28313.3',  'update' : '1.2', 'name' : 'Update 1.2'},
                          {'ver' : '16.131.27701.1',  'update' : '2',   'name' : 'Update 2'},
                          {'ver' : '16.131.28106.2',  'update' : '3',   'name' : 'Update 3'},
                          {'ver' : '16.131.28226.3',  'update' : '3.1', 'name' : 'Update 3.1'},
                          {'ver' : '16.131.28507.4',  'update' : '3.2', 'name' : 'Update 3.2'}
                        ],
                "^17\.":[ {'ver' : '17.143.28621.4',  'update' : '0',    'name' : 'RTW'},
                          {'ver' : '17.143.28912.1',  'update' : '0.1',  'name' : 'Update 0.1'},
                          {'ver' : '17.153.29207.5',  'update' : '1',    'name' : 'Update 1'},
                          {'ver' : '17.153.29522.3',  'update' : '1.1',  'name' : 'Update 1.1'},
                          {'ver' : '17.153.32407.5',  'update' : '1.2',  'name' : 'Update 1.2'}
                        ],
                "^18\.":[ {'ver' : '18.170.30525.1',  'update' : '0',    'name' : 'RTW'},
                          {'ver' : '18.170.30910.2',  'update' : '0.1',  'name' : 'Update 0.1'},
                          {'ver' : '18.170.32404.6',  'update' : '0.2',  'name' : 'Update 0.2'},
                          {'ver' : '18.181.31230.2',  'update' : '1',    'name' : 'Update 1'},
                          {'ver' : '18.181.31626.1',  'update' : '1.1',  'name' : 'Update 1.1'},
                          {'ver' : '18.181.32404.7',  'update' : '1.2',  'name' : 'Update 1.2'}
                        ],
                "^19\.":[ {'ver' : '19.205.33122.1',  'update' : '0',    'name' : 'RTW'}
                        ]        
};

var target_files = [
  'Application Tier\\Web Services\\bin\\Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
  'Application Tier\\Web Services\\bin\\Microsoft.TeamFoundation.WorkItemTracking.Web.dll',
  'Application Tier\\Web Services\\bin\\Microsoft.TeamFoundation.Server.WebAccess.VersionControl.dll',
  'Application Tier\\Web Services\\bin\\Microsoft.TeamFoundation.WorkItemTracking.Server.DataServices.dll',
  'Application Tier\\Web Services\\bin\\Microsoft.VisualStudio.Services.Search.Common.dll',
  'Application Tier\\Web Services\\bin\\Microsoft.VisualStudio.Services.Feed.Server.dll',
  'Application Tier\\Web Services\\bin\\Microsoft.TeamFoundation.Framework.Server.dll'
];

var rel_map = { "^10\." : '2010',
            "^11\." : '2012',
            "^12\." : '2013',
            "^14\." : '2015',
            "^15\." : '2017',
            "^16\." : '2018',
            "^17\." : '2019',
            "^18\." : '2020',
            "^19\." : '2022'
          };

var port = kb_smb_transport();
var appname = 'Microsoft Team Foundation Server';
var kb_base = "SMB/Microsoft_Team_Foundation_Server/";
var vendor = 'Microsoft';
var product = "Team Foundation Server";

var install_num = 0;

registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
var key = "SOFTWARE\Microsoft\TeamFoundationServer";
var subkeys = get_registry_subkeys(handle:hklm, key:key);

var paths = make_list();
var path;

foreach var subkey (subkeys)
{
  if (subkey !~ "^[0-9.]+$") continue;

  var entry = key + "\" + subkey + "\InstallPath";
  path = get_registry_value(handle:hklm, item:entry);

  if (isnull(path)) continue;
    paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

var installs = make_array();
var file_versions = [];
foreach path (paths)
{
  # this DLL is always updated between versions

  var exe = path + "\Tools\Microsoft.TeamFoundation.Framework.Server.dll";
  var ver = hotfix_get_fversion(path:exe);

  version = '';
  rel = '';
  update_ver = '';
  friendly_update = '';
  if (isnull(ver['version'])) continue;

  version = ver['version'];

  #Find file versions
  var file_version_list = collib::map(
    f:function()
    {
      var full_path = hotfix_append_path(path:_FCT_ANON_ARGS[0], value:_FCT_ANON_ARGS[1]);
      var ver = hotfix_get_fversion(path:full_path);
      if(ver.error != HCF_OK) return UNKNOWN_VER;
      return ver.version;
    },
    args:[path],
    target_files
  );

  foreach(var it in collib::enumerate(target_files))
  {
    if(file_version_list[it.index] == UNKNOWN_VER) continue;
    var entry = {path:hotfix_append_path(path:path, value:target_files[it.index]), version:file_version_list[it.index]};
    append_element(var:file_versions, value:entry);
  }
  append_element(var:file_versions, value:{path:exe, version:version});
  
  

  # Find update version
  foreach var maj_ver (keys(update_vers))
  {
    if (version =~ maj_ver)
    {
      rel = rel_map[maj_ver];
      for (i=0; i<max_index(update_vers[maj_ver]); i++)
      {
        update_ver = update_vers[maj_ver][i];
        if (ver_compare(ver:version, fix:update_ver.ver) >= 0)
        {
          update = update_ver.update;
          friendly_update = update_ver.name;
        }
        else
          break;
      }
    }
  }

  set_kb_item(name: kb_base + install_num + "/Path", value: path);
  set_kb_item(name: kb_base + install_num + "/Version", value: version);

  # Azure DevOps partition, UNKNOWN_VER defaults to TFS
  if (ver_compare(ver:version, fix:'17', strict:FALSE) >= 0)
  {
    cpe = "cpe:/o:microsoft:azure_devops_server";
    product = 'Azure DevOps Server';
  }
  else
  {
    cpe = "cpe:/a:microsoft:visual_studio_team_foundation_server";
  }

  if (rel && friendly_update && !empty_or_null(update))
  {
    var ret = register_install(
      app_name        : appname,
      vendor          : vendor,
      product         : product,
      path            : path,
      version         : version,
      product_version : rel,
      display_version : version + " (" + rel + " " + friendly_update + ")",
      extra_no_report : {'Update': update, 'Release' : rel, "Friendly Update" : friendly_update},
      files           : file_versions,
      cpe             : cpe
    );
    
    install_num++;
  }
  else
  {
    register_install(
      app_name : appname,
      vendor   : vendor,
      product  : product,
      path     : path,
      version  : version,
      files    : file_versions,
      cpe      : cpe
    );
    install_num++;
  }
}

hotfix_check_fversion_end();

if (install_num == 0) audit(AUDIT_UNINST, appname);

set_kb_item(name:kb_base + 'NumInstalled', value:install_num);
set_kb_item(name:kb_base + 'Installed', value:TRUE);

report_installs(app_name:appname, port:port);

