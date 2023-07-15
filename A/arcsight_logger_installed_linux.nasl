#TRUSTED a7cf24e80b696321929b9b3d7ae301a5ddfc8e7da748fad1c283b31b6182da69f61fe96d163e0fb7a87999359a05eee7befe0c96aa2f5ece87f60359cd1f28be7de05b19663a12f01989278aab5914d2b316b853e7b0715a41f707ec69a3c803c1aab476782d4ee1b652aeb9ca7466307faf56f1884ccce4eb2ae474ce46358c22e1d19275e982d5854f231abe3ec49094b00d73b7473ea97d99282473a217db9c4679dfabcec96f067e5f8037a742a976d7775f03a77437b0c566df8dcea6fa3577f582fe04f44cbd7300e1bddb40304e269ad993bef4097cc2617971c477b086b1762c833d7fe5ca78933d6f5b493488c0203adba4fffc65b998d2fb2f33b3ec3682653b5f291d967180b683898ccdc6f7ba79cbbd2aaf753d1692f8fbd73ce3004c568ce0fc4b63ccbee75a45b83f6c43fb7380ab72d21d714c004ae79c9ecc35662c44f901151837f7deb6b238815d782202eb4415de4635aa9c2f8f8acb253d80650998cc55f79e9df94ee9e6e7d67138b5f3d5032a7f5cce5d3d535df6d8a5edd390c8541d0f23c229451f7341e99313db02b01b91439455d60e30bb8abc1a60ef0f10463a2222f733b7a93564a78f2c07152695223492e21c3048d82620791427c1f2939d74eb0057c1eb85c816189970b9a6454b49c0cb05081fd8adafd7a45d8292275e5499260338040a4f768e55fa5ebd058f46f7613b545233e4
#TRUST-RSA-SHA256 6eeb93a55a94de5820e0d43ecdff54653ed7e84881b60cf814c9057d2e25ee13b5b4224941d77b3dc376d4dc74551d7b06ca0f2d2752b641d5f3a5282b13b392dea1bf50284a2b53b1e049efaa9b0d2db95343a7b3a508732cd198972463c5fac08f571a533cf503705b6f879d768daa19ad759fca2a2ad45b9a9b073454c44dc4cbb83f2bd6320478a1eb20d38dbc0335b130ee8e79d83f70c7af194d9116dbc07e814def0c71435544cfebec0008a3fd67914e298adf2d6fbe2463f94936a919bdb8aa408dafd83a36d8e2a7bcf786491dbb3c0d4db7530e27711a66d9eed0c03d7e0a6473100790ef20df11d2474f65a6d663f92cc4a6dd6b9e93a87f00b35fcf106d5aff6f16a4b18cf6fd1ab42f204381bcf0998bc2a6a98aa0cc6f86782f3194aab8263f243dd84606449825bab4137c086843bc7b9fe2d2f842474ac30d7599ba392acc3b22fd4ee306c02632948ec50c71a581b699b8a6e0b4db887692f60ebacb8f44df2b10b3edad8bcfa0ebf728b0be59e23e1e3e13d0ec47aec3f3d4e8adf3d1f6959492dfa17933867399ab4c92af013f7c3a389aaf8a162defbf877a31dde862f2d96e05d466f9fae1946f66ceb57c1484408ff828033066775f6eff6e0be0660cdc575ce5ac99c6e856ed571b9b76aae5a55697112defdd90cdfeca5b681edc53a9fb48dfe930963bdd1cac71cb62b65b2eba68efb5db5611
##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(69446);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_name(english:"ArcSight Logger Installed (Linux)");

  script_set_attribute(attribute:"synopsis", value:
"ArcSight Logger is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"ArcSight Logger is installed on the remote host. ArcSight Logger is used to collect and manage logs.");
  # http://www8.hp.com/ca/en/software-solutions/software.html?compURI=1314386#.Ug5u237YUzk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84aa80ae");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include('install_func.inc');
include('local_detection_nix.inc');
include('debug.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");
if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

var app = 'ArcSight Logger';
var cpe = 'cpe:/a:hp:arcsight_logger';

var ver_ui_map = make_array(
  '5.3.1.0',      '5.3 SP1', # Less detail from install-log files
  '5.3.1.6838.0', '5.3 SP1'  # More detail from log files
);

var logger_path = '/opt/current/arcsight/';
var version = UNKNOWN_VER;
var installed = FALSE;

# Use only default install location files for now
var files_and_patterns = make_array(
  logger_path + 'logger/logs/logger_server.out.log', '"\\[INFO \\] Version "',
  logger_path + 'logger/logs/logger_server.log*',     '"\\[INFO \\]\\[Server\\]\\[go\\]\\[main\\] Version "',
  logger_path + 'logger/logs/logger_processor.log*',  '"\\[INFO \\]\\[LoggerProcessors\\]\\[go\\]\\[main\\] Version "',
  logger_path + 'logger/logs/logger_receiver.log*',   '"\\[INFO \\]\\[LoggerReceivers\\]\\[go\\]\\[main\\] Version "'
);

var cmd = 'test -d ' + logger_path + ' && echo OK';
var output = ldnix::run_cmd_template_wrapper(template:cmd);
dbg::log(src:SCRIPT_NAME, msg:'Sending cmd: ' + cmd + '\nResponse: ' + obj_rep(output));
if ('OK' >!< output)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_NOT_INST, app);
}

# Look into each potential data file on the target
var temp_version, res, matches;

# first check the installvariables.properties
cmd = 'grep -h -e "PRODUCT_NAME=" -e "PRODUCT_VERSION_NUMBER=" /opt/UninstallerData/installvariables.properties';
output = ldnix::run_cmd_template_wrapper(template:cmd);
dbg::log(src:SCRIPT_NAME, msg:'Sending cmd: ' + cmd + '\nResponse: ' + obj_rep(output));
matches = pregmatch(string:output, pattern:"PRODUCT_NAME=ArcSight Logger\s.*PRODUCT_VERSION_NUMBER=([0-9.]+)", multiline:TRUE);
if (matches)
{
  version = matches[1];
  installed = TRUE;
}
else
{
  # Check log files 
  foreach var ver_file (keys(files_and_patterns))
  {
    temp_version = '';
    # logger_server.out.log uses a text-based day-of-week and thus, skip sorting date
    # The other files use a fully number-based date and thus, look at them all and sort on date
    if ('.out.' >< ver_file)
      cmd = 'grep -h ' + files_and_patterns[ver_file]  + ' ' + ver_file + ' | tail -n 1';
    else
      cmd = 'grep -h ' + files_and_patterns[ver_file]  + ' ' + ver_file + ' | sort | tail -n 1';
    output = ldnix::run_cmd_template_wrapper(template:cmd);
    dbg::log(src:SCRIPT_NAME, msg:'Sending cmd: ' + cmd + '\nResponse: ' + obj_rep(output));
    res = egrep(string:output, pattern:str_replace(string:files_and_patterns[ver_file], find:'"', replace:''));
    if (empty_or_null(res)) continue;
    installed = TRUE;

    res = chomp(res);
    matches = pregmatch(string:res, pattern:' Version ([0-9.]+)');
    if (!isnull(matches)) temp_version = matches[1];

    # Keep most detailed version number
    if (max_index(split(temp_version, sep:'.')) > max_index(split(version, sep:'.'))) version = temp_version;
  }
}

if(info_t == INFO_SSH) ssh_close_connection();

if (installed)
{
  set_kb_item(name:'hp/arcsight_logger/path', value:logger_path);
  set_kb_item(name:'hp/arcsight_logger/ver', value:version);

  # If we have user-friendly version string, store it
  if (!isnull(ver_ui_map[version])) set_kb_item(name:'hp/arcsight_logger/display_ver', value:display_version);
  else display_version = version;

  register_install(
    app_name:app,
    vendor : 'HP',
    product : 'ArcSight Logger',
    path:logger_path,
    version:version,
    display_version:display_version,
    cpe:cpe)
  ;

  report_installs(app_name:app);
  exit(0);
}
audit(AUDIT_NOT_INST, app);
