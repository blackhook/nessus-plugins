#TRUSTED 7a7c99d3229d7a334e3c4f04b4ffd80fc3b79b61f90fea37f8943141f6a2c9d52060e8592acf58d2a9fc880c6230ac486dd4cbb789d4194f764d61d69a6262ecdebb7e2cd06bbf7768bdd728fc164dfcea3532f768a61bb1bf0c2b7cd408573116880d83fbb609ab31f5216878f3b3b95512d64eaa228f6ff05660437d06ea839918c98f7286e3abcd26fa27a4f07789271cd62ec43805beb7bf189afa4c954eabe9856e104c1a21428dc8e2b90929c0f085f5d37968b638016372f4cb36878782adc315bb5f62d97e22648edd61d71aa63ac8e68e55a47ab208083d956865f8790a94589399c1a8532c917e45bce1cd2ffc73afd0e234d1228f3a971fd1dc274dc0c4d2cc6dab4245c1f51276b680db516ac095513883f19df5559a38f63156a42983bbd70a2d4d3808b0b6072556e5f3d0efa6508652442419d92614629efcb43b9ce4987b1e5f1462f5e419ff72030be1a3219dff7c3c4faa6bd6df2648c0c61dc7bc9e9508ecb28e867e5a594237c72a158a9046b8e87772f10bd9413cdb32f1c3dee654bdee9c8f0edd5f9f3796f9dfe81fd86142cbbbc2ab8a830ee8edfd368b73584f7106eeea71f1173a1b5455c31c3da4dd024c90529a3c94db21f3d08b0601fcfad3f4bf284ad0d454745bd6c8d309ecd4691cd6cdca3ea847095c4e5869da59bcd5da1a68a0fda475b9e5dc82323f95dd73d506bf8dfc7f6a3794
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(67244);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0556");

  script_name(english:"Cisco Prime Data Center Network Manager Installed (Linux)");

  script_set_attribute(attribute:"synopsis", value:"A network management system is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"Cisco Prime Data Center Network Manager (DCNM) is installed on the
remote host. DCNM is used to manage virtualized data centers.");
  # https://www.cisco.com/c/en/us/products/cloud-systems-management/prime-data-center-network-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?946c0157");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/uname");

  exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');
include('install_func.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if ('Linux' >!< get_kb_item_or_exit('Host/uname'))
  audit(AUDIT_OS_NOT, 'Linux');

proto = get_kb_item_or_exit('HostLevelChecks/proto');

installed = FALSE;

if (proto == 'local') info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

jboss_path = info_send_cmd(cmd:'grep ^JBOSS_HOME= /etc/init.d/jboss');
smis_path = info_send_cmd(cmd:'grep ^INSTALLDIR= /etc/init.d/ciscosmis');
java_path = info_send_cmd(cmd:'grep ^JAVA_HOME= /etc/init.d/FMServer');
dcnm_path = NULL;

if (jboss_path =~ '^JBOSS_HOME=')
{
  jboss_path = split(jboss_path, sep:'=', keep:FALSE);
  jboss_path = jboss_path[1];

  # example path: /usr/local/cisco/dcm/jboss-4.2.2.GA
  # everything up to and including "cisco/" is configurable during installation
  # if "dcm" is not in the path, the init script was probably not created by the
  # DCNM installer
  if (jboss_path =~ '/dcm/jboss')
  {
    trailing_dir = strstr(jboss_path, '/jboss');
    dcnm_path = jboss_path - trailing_dir;
    ver_files = make_list(
      '/Uninstall_DCNM/installvariables.properties',
      '/dcnm/Uninstall_DCNM/installvariables.properties',
      '/dcnm/Uninstall_DCNM/InstallScript.iap_xml'
    );
  }
}

if (java_path =~ '^JAVA_HOME=')
{
  java_path = split(java_path, sep:'=', keep:FALSE);
  java_path = java_path[1];

  # example path = /usr/local/cisco/dcm/java/jre1.8
  if (java_path =~ '/dcm/java')
  {
    trailing_dir = strstr(java_path, '/java');
    dcnm_path = java_path - trailing_dir;
    ver_files = make_list('/Uninstall_DCNM/installvariables.properties');
  }
}

if (smis_path =~ '^INSTALLDIR=')
{
    smis_path = split(smis_path, sep:'=', keep:FALSE);
    smis_path = smis_path[1];

    # example path = /usr/local/cisco

    if (!empty_or_null(smis_path))
    {
      dcnm_path = chomp(smis_path) + '/dcm';
      ver_files = make_list('/Uninstall_DCNM/installvariables.properties');
    }
}

# if getting the install path failed for any reason,
# check the default installation directory for 4.x
if (isnull(dcnm_path))
{
  dcnm_path = '/DCNM';
  ver_files = make_list('/Uninstall_DCNM/installvariables.properties');
}

foreach ver_file (ver_files)
{
  file = dcnm_path + ver_file;

  # replace ' with '"'"' to prevent command injection
  file = str_replace(string:file, find:"'", replace:'\'"\'"\'');
  output = info_send_cmd(cmd:"grep '\(^\(PRODUCT_VERSION_NUMBER\|DCNM_SPEC_VER\|INSTALLER_TITLE\)=\|$PRODUCT_NAME$ [0-9.]\+\)' '" + file + "'");

  # if neither of the patterns match, it's likely the file doesn't exist
  # i.e., the command executed above did not get the product version
  ver = NULL;
  match = pregmatch(string:output, pattern:'PRODUCT_VERSION_NUMBER=(.+)');
  if (!isnull(match))
  {
    ver = match[1];
    match = pregmatch(string:output, pattern:'DCNM_SPEC_VER=(.+)');
    if (isnull(match)) match = pregmatch(string:output, pattern:"Data Center Network Manager\(DCNM\) ([\d.]+\([^)]+\))");

    if (isnull(match)) display_ver = ver;
    else display_ver = match[1];
  }
  else
  {
    match = pregmatch(string:output, pattern:"\$PRODUCT_NAME\$ ([\d.]+\(\d+\))");
    if (!isnull(match) && !isnull(match[1]))
    {
      ver = match[1];
      display_ver = ver;
    }
  }

  if (isnull(ver)) continue;

  # convert versions like 5.0(2) to 5.0.2.0
  # it's possible to get a version like this if the .properties file doesn't exist,
  # but the .xml file does
  match = pregmatch(string:ver, pattern:"^([\d.]+)\((\d+)(\w)?\)$");
  if (!empty_or_null(match))
  {
    # convert lowercase letters to numbers
    # a = 1, b = 2, et cetera
    revision = match[3];
    if (isnull(revision)) revision = '0';
    else revision = ord(revision) - 0x60;

    ver = match[1] + '.' + match[2] + '.' + revision;
  }

  installed = TRUE;

  register_install(
    app_name:'Cisco Prime DCNM',
    vendor : 'Cisco',
    product : 'Prime Data Center Network Manager',
    path:dcnm_path,
    version:ver,
    display_version: display_ver,
    cpe:'cpe:/a:cisco:prime_data_center_network_manager'
  );

  break;
}
if(info_t == INFO_SSH) ssh_close_connection();

if (installed) report_installs(port:0);
else audit(AUDIT_NOT_INST, 'Cisco Prime DCNM');
