#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70145);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0622");

  script_name(english:"HPE Network Node Manager i (NNMi) Detection (credentialed check)");
  script_summary(english:"Detects installation of HPE Network Node Manager i (NNMi).");

  script_set_attribute(attribute:"synopsis", value:
"Network management software is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"HPE Network Node Manager i (NNMi) is installed on the remote Windows
host. NNMi is a component of HPE Automated Network Management Suite.");
  # https://www.hpe.com/h41271/404D.aspx?cc=us&ll=en&url=http://domainredirects-sw.ext.hpe.com/saas.hpe.com/en-us/software/network-node-manager-i-network-management-software
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3187f0b");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("install_func.inc");

# {install_path : "...", data_path : "..."} from info in registry.
# Requires that registry connection already be initialized.
function get_nnmi_paths()
{
  local_var hklm;
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  local_var env_key;
  env_key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

  local_var data_dir_item;
  data_dir_item = env_key + "\NnmDataDir";

  local_var install_dir_item;
  install_dir_item = env_key + "\NnmInstallDir";

  local_var items, vars;
  items = make_list(data_dir_item, install_dir_item);
  vars = get_registry_values(handle:hklm, items:items);

  RegCloseKey(handle:hklm);

  if (isnull(vars) || max_index(keys(vars)) < max_index(keys(items)))
    return NULL;

  return make_array(
    "data_path", vars[data_dir_item],
    "install_path", vars[install_dir_item]
  );
}

# Accepts NNMVersionInfo file and returns latest installation/patch.
function extract_ver()
{
  local_var ver_file, info, line, m;
  ver_file = _FCT_ANON_ARGS[0];
  info = [];

  foreach line (split(ver_file, sep:'\n', keep:FALSE))
  {
    line = chomp(line);
    # e.g.  NNMVersion=9.20,9.22.002,9.23.003
    # Most recent version is at the end

    if (empty_or_null(info["Version"]))
    {
      m = pregmatch(
        pattern : "^NNMVersion=(?:\d+\.\d+(?:\.\d+)?,)*?(\d+\.\d+(?:\.\d+)?)$",
        string  : line
      );

      if (!isnull(m))
      {
        info["Version"] = m[1];
        continue;
      }
    }

    m = pregmatch(
      pattern : "^package=(NNM[0-9]+_([0-9]+)),",
      string  : line
    );

    if (!isnull(m))
    {
      # set if no current package or if patch > current patch
      if (empty_or_null(info["Package"]) ||
          ver_compare(ver:int(m[2]), fix:info["Patch"], strict:FALSE) > 0)
      {
        info["Package"] = m[1];
        info["Patch"] = int(m[2]);
      }
    }
  }

  if (!empty_or_null(info))
    return info;

  return NULL;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = "HP Network Node Manager i";

registry_init();

paths = get_nnmi_paths();

if (isnull(paths))
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, app);
}

install_path = paths["install_path"];
data_path = paths["data_path"];

file_retrieval = hotfix_get_file_contents(data_path + "NNMVersionInfo");
# We are done accessing file shares and registry.
hotfix_check_fversion_end();

# Check our attempt to retrieve NNMVersionInfo.
if (file_retrieval["error"] != HCF_OK)
  audit(AUDIT_NOT_INST, app);

info = extract_ver(file_retrieval["data"]);

version = info["Version"];

extra = [];
foreach name (keys(info))
{
  if (!empty_or_null(info[name]) && name != "Version")
    extra[name] = info[name];
}

register_install(
  app_name:app,
  vendor : 'HP',
  product : 'Network Node Manager i',
  path:install_path,
  version:version,
  cpe:"cpe:/a:hp:network_node_manager_i",
  extra:extra
);
report_installs(app_name:app);
