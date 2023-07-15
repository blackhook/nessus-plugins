#TRUSTED 7ff302f380fb17362db5634b25ea1f2061f92c22ad7127056d22bb6cc0d8e58c42b289e6c0d3c038331031a3614efe4d8b9716af538fe3cdc6010d13f97e4ecefff3dc455f1b4b053757de4eb710ef9844f2d76c6c1c671bddaba7e993ec11023efb832915ff294c4c64f0204173f7fb5c65b25d81042309ec14b8da11a14a7bb958a0ed5570da40eb4983aa433d84f333938f6b4e833c02d17caf4d3162bbe2a42b7a982814bf4c55d9fb056a6255ec7a6694c132e0ba52ee2b4d15819d5c76b3dcc5e010920b02ee3268da3c34fa105e3c64c5144740778f31efaa22a5f4e7980c6e14d509bd5ad5fab806c5c2f7487293caed5fba1524e339a0fcb19745cac04d139cb510ee5602587cc3f276d1afe509735346dc33171951d11391121d8d1537857b541991d55a83dfb5c1cfe27da8140dd87cf5b61371ccb49673650dc003b330dd6a232182a1927dfddc567ce337beb7b71dcad5faf39f5478fd6493f504e25a0aa9d3ee5b60641c47afad54a650b4c114e60616f21e8b748c78b5228d2521fff3fc7ed9e56baa9b8dea64105f104f174a4a60bdb76a85cbcf37dc88432519b5346558cd332e2de1672e43db519fb24b24a4188e93cd2eae8010710f92f10d77d5f4f1b38a50b2f80f7598ace67276343fa42ffc76ff88fec5abf70fb0c0d10c722cc1e2a6770e6bfb415237e6d159a318d9e1ff9c226bf134999e80bc
#TRUST-RSA-SHA256 9cd1a7c3184fa3f2ce6d87ce9793211fc5e21bcadbf95dfe8d24f490e978349f86b7a59bbc132376f1bba7ff2c1e8988e2a36f0612ade48820120301d8a9d7fa66f2bcfcf3a752839e7e2da382a490d251872826e547806127c29f8482d4448bef8e453edf9f4bf0a480390ed9edddbe598535e40bffb9f1e095500cce561c76450021685fd01844d95ad6e3e85926083bb9dc2dd6570397b193952167e207a20f2fb3aa5e34d55ad758490c6dc76ebb874044a397d4b8be75a4985ac5bd88822d1f91030deb1ea7f9d5fcaeba6f787eeafd51d0f6a1f499035abe25609f62ee27df619cf34097f94ff9a85e4c1fa1355bb5560459fe2ec131c95371cd61dcb3233ed84073728e83c8c57a6e638b7f02eef0740ac981427836dd8d6f0a9e3817e5e17a1833b0f4bef894577e023fbe61dddba989256f4350ca2be7ae030a927fb8447bc75b73affc4bc02aa6cacce9a2a96e1150f4dc62676a75c063673e8c3d84309fa027877b1e49d4697bd59fc7af495e302d78d043cdeba7b7c72bec13910410d344195230c8de79c80ede9a25f28c88a79c4f6cc31adb5dc4e18a0d0592c62c86a8015416e8ca727699cf31f4d6614329dc89018799dafa53386b80707118ad89caf42c7fc63f34ab975d7b0740c6417e200d4a8bc21963e3ba4ff6300967c61aa2943477d06b769d6426f94f6f607a0b026dccb750cc3d6276d82e4422
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70138);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"IBM Tivoli Access Manager for e-Business / IBM Security Access Manager for Web Installed Components");
  script_summary(english:"Obtains components version information.");

  script_set_attribute(attribute:"synopsis", value:
"An access and authorization control management system is installed on
the remote host.");
  script_set_attribute(attribute:"description", value:
"IBM Security Access Manager for Web, formerly IBM Tivoli Access
Manager for e-Business, is installed on the remote host. The
application is an access and authentication control management system.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20151007121318/http://www-03.ibm.com/software/products/en/access-mgr-web");
  # http://web.archive.org/web/20180113184703/http://www-03.ibm.com:80/software/products/en/category/identity-access-management
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e68f5311");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_access_manager_for_e-business");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

proto = get_kb_item_or_exit('HostLevelChecks/proto');
get_kb_item_or_exit("Host/local_checks_enabled");

# Do not run against Windows and some UNIX-like systems
# to avoid, among other things, Cisco, embedded devices,
# and so forth.
os = get_kb_item_or_exit('Host/OS');
os = tolower(os);
if (
  'linux' >!< os &&
  'aix' >!< os &&
  'solaris' >!< os
) audit(AUDIT_OS_NOT, "a supported OS");

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

# Check if pdversion exists
default_pdversion_path = "/opt/PolicyDirector/bin/pdversion";
output = info_send_cmd(cmd:"test -x " + default_pdversion_path + " && echo OK");
if ("OK" >!< output)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_NOT_INST, 'IBM Access Manager for e-Business / IBM Security Access Manager');
}

# pdversion with no options only outputs the basic components, so
# need to specify all keys to get all info.
# Further, TAM and SAM support different values for '-key'
# so look for one, then the other and exit if neither is present
output = info_send_cmd(cmd:default_pdversion_path);

res = egrep(string:output, pattern:"IBM Tivoli Access Manager ");
if (strlen(res))
{
  # TAM is present
  component_keys = 'pdacld,pdauthadk,pdjrte,pdmgr,pdmgrprxy,pdrte,pdsms,pdweb,pdwebars,pdwebadk,pdwebrte,pdwpi,pdwsl,pdwpm,tivsecutl';
  app_name = 'IBM Tivoli Access Manager for e-Business';
}
else
{
  res = egrep(string:output, pattern:"Security Access Manager ");

  # If still nothing matching, neither TAM or SAM are installed; exit.
  if (!strlen(res))
  {
    if (info_t == INFO_SSH) ssh_close_connection();
    exit(1, "'" + default_pdversion_path + "' exists on the remote host, however, it provided no useful output.");
  }

  # SAM is present
  component_keys = 'pdacld,pdauthadk,pdjrte,pdmgr,pdmgrprxy,pdrte,pdsms,pdweb,pdwebadk,pdwebars,pdwebpi,pdwebpi.apache,pdwebpi.ihs,pdwebrte,pdwpm,tivsecutl';
  app_name = 'Security Access Manager for Web';
}

appears_to_be_installed = TRUE;

# Call pdversion again, but with option to list all components
output = info_send_cmd(cmd:default_pdversion_path + " -key " + component_keys);
if (info_t == INFO_SSH) ssh_close_connection();
res = egrep(string:output, pattern:"(IBM Tivoli Access Manager|(IBM )?Security Access Manager|IBM (Tivoli )?Security Utilities)");
if (!strlen(res))
  exit(1, "'" + default_pdversion_path + "' exists on the remote host, however, it provided no useful output when using the '-key' option.");

res_lines = split(chomp(res));
info = "";
version = UNKNOWN_VER;
components = make_array();

# Components and versions output from pdversion are in the format :
# IBM Tivoli Access Manager Policy Server                6.1.0.0
# IBM Tivoli Access Manager Policy Proxy Server          Not Installed
#
# Note : for the newer Security Access Manager, the output lines
#        will contain 'Security Access Manager ' rather than
#        'IBM Tivoli Access Manager'.

# Get component and version from each line
foreach res_line (res_lines)
{
  if ("Not Installed" >< res_line) continue;

  matches = pregmatch(
    string:res_line,
    pattern:"^((IBM Tivoli Access Manager|(IBM )?Security Access Manager|IBM (Tivoli )?Security Utilities).*) ([0-9.]+)$"
  );
  if (isnull(matches)) continue;
  component = strip(matches[1]);
  component_ver = matches[5];

  # Use the version of the runtime component
  if (component == "IBM Tivoli Access Manager Runtime")
    version = component_ver;
  info += '\n' +
    '  Component : ' + component + '\n' +
    '  Version   : ' + component_ver + '\n';
  set_kb_item(name:'ibm/tivoli_access_manager_ebiz/components/'+component, value:component_ver);
  components[component] = component_ver;
}

if (appears_to_be_installed)
{
  set_kb_item(name:'ibm/tivoli_access_manager_ebiz/pdversion_path', value:default_pdversion_path);

  register_install(
    vendor:"IBM",
    product:"Tivoli Access Manager for e-Business",
    app_name:'IBM Access Manager for e-Business / IBM Security Access Manager',
    path:default_pdversion_path,
    version:version,
    cpe:"cpe:/a:ibm:tivoli_access_manager_for_e-business",
    extra:components
  );

  if (report_verbosity > 0)
  {
    if (info)
      report =
        '\n' + app_name + ' appears to be installed.' +
        '\nThe following file was used to discover the components listed' +
        '\nfurther below :' +
        '\n\n' +
        '  File : '+default_pdversion_path +
        '\n' +
        '\n' + info;
    else
      report =
        '\n' + app_name + ' appears to be installed,' +
        '\nhowever, no components or version information could be obtained.' +
        '\n' +
        '\nThe following file was used to discover the presence of' +
        '\n' + app_name + ' :' +
        '\n\n' +
        '  File : '+default_pdversion_path +
        '\n';
    security_note(port:0, extra:data_protection::sanitize_user_paths(report_text:report));
  }
  else security_note(0);
  exit(0);
}
audit(AUDIT_NOT_INST, 'IBM Tivoli Access Manager for e-Business / IBM Security Access Manager');
