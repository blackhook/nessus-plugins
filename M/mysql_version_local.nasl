#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129468);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_name(english:"MySQL Server Installed (Linux)");
  script_summary(english:"Checks for MySQL Server on Linux");

  script_set_attribute(attribute:"synopsis", value:
"MySQL Server is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"MySQL Server is installed on the remote Linux host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Host/RedHat/release", "Host/CentOS/release", "Host/Debian/release", "Host/Ubuntu/release");

  exit(0);
}

include('install_func.inc');
include('local_detection_nix.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

ldnix::init_plugin();
info_connect(exit_on_fail:TRUE);

var release, packages, regex;
var cpe='cpe:/a:mysql:mysql';
var timeout, depth=10, res, path, buf;
var exclude_dirs = ['/bin', '/boot', '/dev', '/etc', '/lib', '/media', '/mnt', '/proc', '/run',
    '/sbin', '/srv', '/sys', '/tmp'];

# Determine OS and installed packages
var oses = [ "CentOS", "Debian", "RedHat", "Ubuntu" ];
foreach os (oses)
{
  release = get_kb_item("Host/" + os + "/release");
  # Supported OS detected
  if (!empty_or_null(release))
  {
    # Get package list
    if (os == "Debian" || os == "Ubuntu")
    {
      packages = get_kb_item("Host/Debian/dpkg-l");
      regex = "^ii +(mysql-server-core-[0-9\\.]+ +([0-9\\.]+-[0-9][\+]?[a-z]+[0-9\\.].*? ).*)$";
    }
    else
    {
      #see link for package names, looking for Database server and related tools
      #https://dev.mysql.com/doc/refman/8.0/en/linux-installation-rpm.html
      packages = get_kb_item("Host/" + os + "/rpm-list");
      regex = "^(mysql-(community|commercial)-server-([0-9\\.]+-?[0-9])[^\|]+).*$";
    }

    if (empty_or_null(packages)) audit(AUDIT_PACKAGE_LIST_MISSING);
    break;
  }
}

if (empty_or_null(release))
  audit(AUDIT_OS_NOT, join(oses, sep:" / "));


# Determine if MySql Server is installed and attempt to get version
app = 'MySQL Server';

matches = pgrep(pattern:regex, string:packages);
if (empty_or_null(matches)) dbg::detailed_log(lvl:1, msg:'MySQL Server does not seem to be installed via System Package Manager.');

foreach package (split(matches, sep:'\n'))
{
  matches = pregmatch(pattern:regex, string:package);
  if (empty_or_null(matches)) continue;
  
  extra = {};
  extra["Package"] = matches[1];

  version = UNKNOWN_VER;
  if (os == "Debian" || os == "Ubuntu")
  {
    if (!empty_or_null(matches[2]))
      version = matches[2];
  }
  else #for rpm, there is distinction between commercial and community so the version is in the 3rd block
  {  
    if (!empty_or_null(matches[3]))
      version = matches[3];
  }
  register_install(
    app_name : app,
    vendor : 'MySQL',
    product : 'MySQL',
    path     : '/usr/sbin/mysqld',
    version  : version,
    extra_no_report:make_array( 'Detection', 'Local'),
    cpe      : cpe
  );
}

###
# Search MySQL Server instances distributed via self-contained tarball
###

if (thorough_tests)
{
  timeout = 1800;
  depth = 99;
}

# the config file for package installed mysql-server is /etc/my.cnf
var mysql_config_files = ldnix::find_executable(paths:'/', bin:'mysql_config', timeout:timeout, depth:depth, excluded:exclude_dirs);
if (isnull(res)) dbg::detailed_log(lvl:1, msg:'No MySQL Server found on this server.');

# check the existence of some other files to ensure it's a complete install instead of just a file
var pattern = "version='([0-9.]+)'";

foreach var mysql_config_file (mysql_config_files)
{
  path = mysql_config_file - 'mysql_config';
  if ( ldnix::file_exists(file:path+'mysqld') && 
      ldnix::file_exists(file:path+'mysql') && 
      ldnix::file_exists(file:path+'mysqlcheck') 
  )
  {
    buf = ldnix::run_cmd_template_wrapper(template:strcat('grep -E "', pattern, '" $1$'), args:[mysql_config_file]);
    if (empty_or_null(buf))
    {
      version = UNKNOWN_VER;
    }
    else
    {
      match = pregmatch(string:buf, pattern:pattern);
      if (match) version = match[1];
    }

    register_install(
      app_name : app,
      vendor  : 'MySQL',
      product : 'MySQL',
      path    : path,
      version : version,
      extra_no_report:make_array( 'Detection', 'Local'),
      cpe      : cpe
    );
  }
}
if (info_t == INFO_SSH) ssh_close_connection();
get_install_count(app_name:app, exit_if_zero:true);

report_installs(app_name:app);