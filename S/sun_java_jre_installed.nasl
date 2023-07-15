#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33545);
  script_version("1.54");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0690");

  script_name(english:"Oracle Java Runtime Environment (JRE) Detection");
  script_summary(english:"Checks for Oracle/Sun JRE installs.");

  script_set_attribute(attribute:"synopsis", value:
"There is a Java runtime environment installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"One or more instances of Oracle's (formerly Sun's) Java Runtime
Environment (JRE) is installed on the remote host. This may include
private JREs bundled with the Java Development Kit (JDK).

- Additional instances of Java may be discovered if thorough
  tests are enabled.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/technetwork/java/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/18");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("java_jre_installed_win.nbin");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("install_func.inc");

app = "Java Runtime";
cpe = "cpe:/a:oracle:jre";
prod_name1 = "Oracle Java";
prod_name2 = "Sun Java";
related_app = "Java";

##
#  Note: Several instances of Java may have been found.
#        The plugin is intended to branch/fork here
##
found_java = get_single_install(app_name:related_app);

app_found = FALSE;
if (!empty_or_null(found_java['Application']) &&
    (found_java['Application'] == prod_name1 || found_java['Application'] == prod_name2))
  app_found = TRUE;

if (!app_found)
  exit(0, "The Java instance detected does not appear to be " + app);

path = found_java['path'];
version = found_java['version'];
display_version = found_java['display_version'];
bin_locs = found_java['Binary Location'];

##
#  Correct formatting (downstream plugins have fewer
#   labels than main Java Detection plugin)
##
if ('\n                     ' >< bin_locs)
  bin_locs = str_replace(string:bin_locs, find:'\n                     ', replace:'\n                    ');

extra = make_array();
extra['Binary Location'] = bin_locs;

register_install(
  app_name:app,
  vendor : 'Oracle',
  product : 'JRE',
  path:path,
  version:version,
  display_version:display_version,
  cpe:cpe,  
  extra:extra
);

report_installs(app_name:app);

exit(0);


