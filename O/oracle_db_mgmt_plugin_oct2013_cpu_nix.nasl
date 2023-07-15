#TRUSTED 302c294db59867b9517a5b30a6e4f57a3a291c7f37eb83995c1274be65ffe4fb8135560c7a7e34673514f8d56582f549f21d90c6babb5dbcb2073d1d100b1b050e532251ea718c5005afe6fdddb7fcd1d5c41f1494847525e79f19cfe0dd506519327be586cebea8004e14d0ce1c2a8efa279c953b76fec5b5ca42b4ab4ad52d10210372b5d72f45fa1d9d6aedd2b7309e2f8531ee1772887af5d450be81d1c037009e6b2c0c1d593adf1843ad74eba5d2758bacafaee2b3c8b6f3e9033c7fa6630d7968e618913d9d4d961c0982cd99d66029c6a1cb70269ddff6c01c80fdb42e1719b754895249c1c382d531e78494555eed998939627bcc7aa859e7738d64c53154912d973473a824e3734631e48f22299231420c558ccaa5fe632cac617e89b0123e7e9f640d412852e65cbc242aeb08796e55513c9d72cffdc9e875f1dbf1410f640415a202ddf5a0596843d1536f48cfcf1a945f12203da10144fdf23a2450b88993ab6695c989b27d079ecd552adb369c89453ad267bb426853ccef97070b21e2ce464ababc82c1da89b982c7ebb451d5071ada2c3610d159e038a92851d0e9951a242f36fbb7b2d73a2de47f397b9265b9087ad19e4abb999cbb7415061e03cbbf35788680531196907ef9ff3c0267a0e7f6e0b74508eb4729edf35a390621be331afcd1fc98c164b4bbf74c1709860b7aa6385ef06f558ec36d32f1
#TRUST-RSA-SHA256 917eebb8c13c5c27f1c2b5c8e5aeafb50d0872386eaeb2ff42a1df3bc9f6413d2c7d8518b95e61879f7acf826ba4eb85f8fe9fb2b6bfd848248e761a72a1f2efce2f4ddd644f9ac74b267d7d7517ee27aca2c0cc650cf0f3496c3cbfcb78a850402d7391cd32677bcf66b1162e5b0662874207bfa84a15f811aa91c1d221674645b2ddf1a5eaf5d6ef9352edc0256c659f3e3541baafebefe797454233725b4e16a94dce9d6c512a298206c61142f69fd4904778bdb9e94d4dad980874deff1c5db463703d3482d80e34c7751b5ffbcd246a10a2f0f10fe5b0402931bc4ce8e7c99c1533c61a9fda8b45592b4c90af0d1a2d038bfed8d080c9cb7c57726556ef249d47f1f1cdffc7b23aa7fa184df0ec9dcd96e3d9611bcbf3578834783f664a6e7bf520b23bf47b390095b24227d08db48dbc9d10fe9004e286b93f82fef6e64995b8186692268053bd45f6f260336ae5d215d6d87672cb14b34179ce84058e51a281956d86d78d23455af87d0ca7d4c64d8b95a5cc38b56f849b1ac40ccbd4e1e8c6e082874cf57337eb38d92b1af3d3fb9156c4b69bc36ca07fd143314294f5535ad161991f9dbf2aa070f299460d9c651f1fcfabcd429f8b500829de7b2ccc1f1c6606b93246feb8f8cd8c21851b784aba8e36636bbead9a65aa76b4c8dcb1ab2fff5bda6c0a80ba193a13e46964649fab19f5c454ef8de19688b9a29cf2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70546);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_cve_id(
    "CVE-2013-3762",
    "CVE-2013-5766",
    "CVE-2013-5827",
    "CVE-2013-5828"
  );
  script_bugtraq_id(
    63056,
    63064,
    63068,
    63071
  );

  script_name(english:"Oracle Database Management Plug-In Unix (October 2013 CPU) (credentialed check)");
  script_summary(english:"Checks for patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"A database management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle Database Management Plug-In installed on the remote host is
missing the October 2013 Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities in the Enterprise
Manager Base Platform component :

  - An unspecified flaw exists in the Schema Management
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2013-3762)

  - An unspecified flaw exists in the DB Performance
    Advisories/UIs subcomponent that allows an
    unauthenticated, remote attacker to impact integrity.
    (CVE-2013-5766)

  - Multiple unspecified flaws exist in the Storage
    Management subcomponent that allow an unauthenticated,
    remote attacker to impact integrity. (CVE-2013-5827,
    CVE-2013-5828)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2013 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_plugin_for_database_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("local_detection_nix.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!is_sh_command_line_os()) exit(0, "Oracle Database Management Plug-In checks are not supported on the remote OS at this time.");

# We may support other protocols here
if ( islocalhost() )
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# Find the inventory.xml file and read it in
# Parse the results to get the paths and version of the DB plugins
var info = "";

var cmd = 'cat /etc/oraInst.loc';
var cmd2 = "";
var buf = NULL;
var buf0 = NULL;
var args = [];

var path, version, item, chunk;
var paths = make_array();
var results = make_array();
buf0 = info_send_cmd(cmd:cmd);

# We want to handle that Grep and Sed within the plugin itself. This'll help breakup that large command
# and be more reliable then trusting the target box)
if (!empty_or_null(buf0))
{
  cmd2 = 'cat ';
  foreach item (split(buf0))
  {
    # Find any instances  starting with inventory_loc= (It should be a path)
    results = pregmatch(pattern:"inventory_loc=(.*?)(?:$|\n)", string:item);

    if (!empty_or_null(results) && !empty_or_null(results[1]))
    {
      append_element(var:args, value:results[1] + '/ContentsXML/inventory.xml');
      cmd2 += " '$" + max_index(args) + "$'";
    }
  }
}

# Here, we do the second cat in the original command. This will cat all the contents from the valid paths we discovered!
if (!empty_or_null(args))
{
  buf = ldnix::run_cmd_template_wrapper(template:cmd2, args:args);
}

# continue with original code here. 
# NOTE: that this is only going to look for the first instance of oms12c. We might come back to this later and adjust it
# to handle multiple instances (In the event that we have them)
if (buf)
{
  buf = chomp(buf);
  if ('HOME NAME="oms12c' >< buf)
  {
    chunk = strstr(buf, '<HOME NAME="oms12c') - '<HOME NAME="oms12c';
    chunk = strstr(chunk, '<REFHOMELIST>') - '<REFHOMELIST>';
    chunk = chunk - strstr(chunk, '</REFHOMELIST>');
    chunk = chomp(chunk);

    foreach item (split(chunk))
    {
      path = '';
      # If the item is a DB 12.1.0.3 or 12.1.0.4 plugin, save the path
      if (item =~ "/oracle\.sysman\.db\.oms\.plugin_[^/0-9]*12\.1\.0\.[2-4]($|[^0-9])")
      {
        path = ereg_replace(pattern:'^\\s+<REFHOME LOC="([^"]+)".*', string:item, replace:"\1");
        version = strstr(path, 'plugin_') - 'plugin_';
        paths[version] = path;
      }
    }
  }
}

if (max_index(keys(paths)) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, "No affected Oracle Database Management Plug-Ins were detected on the remote host.");
}

# Loop over the DB Management Plug-In paths
info = '';
var patchid;
foreach version (keys(paths))
{
  if ('12.1.0.2' >< version) patchid = '15985383';
  else if ('12.1.0.3' >< version) patchid = '17171101';
  else if ('12.1.0.4' >< version) patchid = '17366505';

  path = paths[version];
  buf = ldnix::run_cmd_template_wrapper(template:"cat '$1$'", args:[path + "/.patch_storage/interim_inventory.txt"]);

  if (empty_or_null(buf))
    info += '  ' + version + '\n';
  else
  {
    # Parse the file to see what patches have been installed
    buf = chomp(buf);
    chunk = strstr(buf, '# apply: the patch to be applied.') - '# apply: the patch to be applied.';
    chunk = chunk - strstr(chunk, '# apply: list of patches to be auto-rolled back.');
    if (!empty_or_null(chunk))
      chunk = chomp(substr(chunk, 1));

    if (patchid >!< chunk)
      info += '  ' + version + '\n';
  }
}
if (info_t == INFO_SSH) ssh_close_connection();

if (info)
{
  var report =
    '\nThe following affected Oracle Database Managment Plug-Ins were detected' +
    '\non the remote host :' +
    '\n' +
    info;
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : report
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
