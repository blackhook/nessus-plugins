#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79802);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_xref(name:"IAVT", value:"0001-T-0622");

  script_name(english:"HPE Network Node Manager i (NNMi) Linux Detection (credentialed check)");
  script_summary(english:"Detects installation of HPE Network Node Manager i (NNMi).");

  script_set_attribute(attribute:"synopsis", value:
"Network management software is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"HPE Network Node Manager i (NNMi) is installed on the remote Linux
host. NNMi is a component of HPE Automated Network Management Suite.");
  # https://www.hpe.com/h41271/404D.aspx?cc=us&ll=en&url=http://domainredirects-sw.ext.hpe.com/saas.hpe.com/en-us/software/network-node-manager-i-network-management-software
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3187f0b");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("install_func.inc");
include('local_detection_nix.inc');

ldnix::init_plugin();

var appname = "HP Network Node Manager i";

var rpms = get_kb_list("Host/*/rpm-list");
if(empty_or_null(rpms)) audit(AUDIT_PACKAGE_LIST_MISSING);
var distro = keys(rpms);
distro = distro[0];
rpms   = rpms[distro];

# Get the RPM version
var version = pregmatch(string:rpms, pattern:"(^|\n)HPOvNnmAS-([0-9.]+)-\d+\|");
if (empty_or_null(version)) audit(AUDIT_VER_FAIL, appname);
version = version[2];

var extra = [];
var rpm_array, item, rpm_match, hs_match;

##
#  We may have more than a single match found in the following
#   so a new variable will track 'high score' of patch version
##
hs_match = NULL;

rpm_array = make_list();
rpm_array = split(rpms);
foreach item (rpm_array)
{
  rpm_match = NULL;
  rpm_match = pregmatch(string:item, pattern:"(?:^|\n)(NNM[0-9]+L([0-9]+))-[0-9]");
  if (!empty_or_null(rpm_match))
  {
    if (empty_or_null(hs_match))
    {
      # set initial match for patch version
      hs_match = rpm_match;
    }
    else
    {
      # Check to see if the current patch version is greater than those already processed
      if (int(rpm_match[2]) > int(hs_match[2]))
      {
        # new high patch version found
        hs_match = rpm_match;
      }
    }
  }
}

if (!isnull(hs_match))
{
  extra["Package"] = hs_match[1];
  extra["Patch"] = int(hs_match[2]);
}

register_install(
  app_name:appname,
  vendor : 'HP',
  product : 'Network Node Manager i',
  path:"/opt/OV", # Nix installer gives you no choice for this
  version:version,
  cpe:"cpe:/a:hp:network_node_manager_i",
  extra:extra
);
report_installs(app_name:appname);
