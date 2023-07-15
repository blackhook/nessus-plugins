#TRUSTED 543130595694c2f9f728769e990fed2fec01ef2dbdace7073290c21d6964423b0b599a35c124921c700e9a77c6a06c838f762c349db626c7056f0a2451194ca87ed6f075864ea6866af74f0e58e59e22bd781be7d6b1f1d09f0a1450a6350e22d89313494f64c25eb8bb0244e301626f0535b5a9a48f185ea3a68cedc4c92543673a522e49d23eac429170fb5bc28bb7029acf523151d403640575c75637e0028a1f48d8bb96b2998df4a5a83e96bdcdca4f5a2c61f408f3572dee2d65e8d34e15f37fbbc3c6c04d8e930e6dfde9c8bbc732945e1b9b2126bfd59597e5c0cd836c6d60e10ed951974c3faf1fbe20786ea2f8b8297489a55415981fae9827f497521c6b99dca6b069c4ec4bc435a1940326e7ac22b73c94bd0b316ee4363f88bc700fb1dd1fb91bcad84cb2c7edef44a6b6e7be4f759a1b2083757d5c1c83d624fdb85bdbaa3f096da7003d9d4d878e1be26d741a1def2890e307acc804cab80e12afd741fd102547fbbfe352661165b143f7469f752ca34a651e268f900ed3a0d165436eec813014f06af703369f0d65c75819735d17d01dc61360e0e629e9530aef7d0e3d05697207bb1888fbd671459f909af526b07a1ca832004c0101d72453002891bb3026003bee48944d44f5fb8916cdc65ea99594ad00480cea6c80d68180e0b63ddf9c4c4c105f937005beac58f3324813bc53a49a5521907967f6bf
#TRUST-RSA-SHA256 4084a5abdedd86277abf223b7ea23a303e29737a725f65f7a9414e6569590cf37ab70f5fa4c438c3559ee358d19c4a8c8f4258ce23f1bd20c92fa9c3958d9b6f742abec7327f50c736f9374db38e087cce147a6fe8085679bb6279f8e7f22df3be24cb424208d872c0eeb8ac636ea204f5f134b9fc5cc06b57da3296123df192d160d7ab4e75b6225b50aa96b8421d01a401844307c462e0defe20007add4df7a358cc914b24f53d50c1b76f48b83381974fa5165da030ee37c29b2926f79253ac18bb078957c546ab03585295155405ece2bbdf59213627d198a66f1a68d9716b05f568972500f2a135a829d288ba0bbd3a4bb602d64ea353387059a03dec762aabdead2d2b30e1f94344adbe752289ffd025843b19f530e82ae5173d5e4fd5b161395ec9ab110df99becfd578dcee32e406228275e4325e3edcf5e4d8e36f29845e3a9c946dde188938fdd5efe492c2ce5cabac93aeb8fb28ea6c791ea264e880641c1b6b2a1f84f475d185d9e8a1c0400bcb7f402be76925200fd8656854d30c1dc1151cb468190c3cbb74a0824b4663c3648f6651440e3b0a9366f04339829d6d26585e9b6a53e04e8829f5aaf5a70048648178ea2bf6acd73966b80fc105fe93ca6bfe205d1255882ec6278bbad6acf3d6986ce8799b6086b22e4bf38468b590f819f92bdb1b042146cb9dcf1bef79f1846e9ba2856b48cd7355dcab632
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122501);
  script_version("1.18");

  script_name(english:"SSH Rate Limited Device");
  script_summary(english:"Attempts to login to remote device and determine if SSH connections are rate limited.");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a SSH rate limited networking device that may
cause intermittent authentication failures throughout the scan.");
  script_set_attribute(attribute:"description", value:
"The remote host is a device that may rate limit connections,
potentially causing intermittent authentication failures in
other plugins.  Local checks will be enabled in this plugin
where possible.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_settings.nasl", "clrtxt_proto_settings.nasl", "ping_host.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

include("datetime.inc");
include("string.inc");
include("byte_func.inc");
include("misc_func.inc");

include("ssh_func.inc");
include("ssh_lib.inc");
include("ssh_get_info2.inc");
include("agent.inc");
include("ssh_rate_limit.inc");
include("telnet_func.inc");
include("junos.inc");

# should not be included in agent. disable here to be sure.
if(agent()) exit(0,"This plugin is disabled on Nessus Agents.");

start_time = gettimeofday();
enable_ssh_wrappers();

if(islocalhost())
{
  info_t = INFO_LOCAL;
}
else info_t = INFO_SSH;

session = new("sshlib::session");
# disable compression
sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_server_to_client"] = "none";
sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_client_to_server"] = "none";

if(get_kb_item("global_settings/enable_plugin_debugging"))
  SSH_DEBUG = TRUE;

# login with placeholder value for channel. new_channel is passed by reference so it will be
# picked up later in plugin.
channel = session.get_channel();
login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:TRUE,
                                              rate_limit:TRUE, new_channel:channel, force_none_auth:TRUE);


if(!login_res)
{
  # remove the failure so that plugins down the chain can verify after service detection
  rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed");
  session.dbg_log(message:'Login via sshlib::try_ssh_kb_settings_login has failed.');
  session.close_connection();
  audit(AUDIT_FN_FAIL, 'sshlib::try_ssh_kb_settings_login');
}


# determine authentication type from try_ssh_kb_settings_login
sonicwall_none = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "sonicwall/none");
sonicwall_password = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "sonicwall/passwordauth");
junos_auth = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "junos/auth");
omniswitch_auth = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "omniswitch/auth");

if(!sonicwall_none && !sonicwall_password && !junos_auth && !omniswitch_auth)
{
  session.close_connection();
  exit(0,"Device is not identified as a connection limited system.");
}

# sh shell handler set in try_ssh_kb_settings_login()
sh = channel.shell_handler;

# sonicwall device
if(sonicwall_password || sonicwall_none)
{

  report_no_command_sw = "The remote host has been identified as a SonicWall device" + '\n' +
                         "that may be rate limiting SSH connections." + '\n';
  report_no_command_sw += "As a result there may be intermittent authentication failures" + '\n' +
                          "reported for this device." + '\n\n';
  report_no_command_sw += "Attempts to run commands to gather more information on" + '\n' +
                          "the device have failed." + '\n';
  # run commands on sonicwall device using sh shell handler 'raw' commands for limited shell handling functionality
  # sonicwall devices only have one login mode unlike junos which has a shell mode and cli mode
  var cmd_out = get_kb_item('flatline/sonic_sh_run_command');
  if(empty_or_null(cmd_out))
  {
    cmd_out = sh.run_command(channel:channel, command:"show device", raw:TRUE, cmd_timeout_min:60, sonicwall:TRUE);
    if(!check_command_output(data_buf:cmd_out))
      cmd_out = sh.run_command(channel         :channel,
                               command         :"show version", 
                               raw             :TRUE, 
                               cmd_timeout_min :60, 
                               sonicwall       :TRUE);
  }
  if(!check_command_output(data_buf:cmd_out))
  {
    # if failed to run commands exit without setting KB items - something went wrong.
    # legacy library will attempt to authenticate and run commands in ssh_get_info.nasl
    if(empty_or_null(cmd_out))
    {
      session.dbg_log(message:'Failed to run commands on SonicWall device: no data received after opening shell.');
    }
    else
    {
      session.dbg_log(message:'Failed to run commands on SonicWall device. Returned: ', cmd_out);
    }
    session.close_connection();
    security_report_v4(
      port       : session.port,
      severity   : SECURITY_NOTE,
      extra      : report_no_command_sw
    );
    exit(0);
  }

  os_name = "SonicOS";
  up_time = "unknown";

  # sonicwall < 6
  if("Firmware Version: SonicOS" >< cmd_out)
  {
    set_kb_item(name:"Host/SonicOS/show_device", value:cmd_out);
    write_compliance_kb_sonicwall(command:"show device", result:cmd_out);
    os_line = pgrep(pattern:"^Firmware Version:", string:cmd_out);
    if (os_line)
    {
      os_line = chomp(os_line);
      match = pregmatch(pattern:"^Firmware Version: SonicOS ((Enhanced|Standard) [0-9][^ ]+)", string:os_line);
      if (!isnull(match)) os_name += " " + match[1];
    }
    model_line = pgrep(pattern:"^Model:", string:cmd_out);
    if (model_line)
    {
      model_line = chomp(model_line);
      match = pregmatch(pattern:"^Model: (.+)", string:model_line);
      if (!isnull(match)) os_name += " on a SonicWALL " + match[1];
    }
    # Collect time of last reboot.
    if ("Up Time:" >< cmd_out)
    {
      foreach var line (split(cmd_out, keep:FALSE))
      {
        if (preg(pattern:"^Up Time: [0-9]", string:line))
        {
          up_time = line;
          break;
        }
      }
    }
  }
  # sonicwall 6 and 7
  else if('firmware-version "SonicOS' >< cmd_out)
  {
    if ('SonicOSX' >< cmd_out) os_name = 'SonicOSX';
    set_kb_item(name:"Host/SonicOS/show_version", value:cmd_out);
    write_compliance_kb_sonicwall(command:"show version", result:cmd_out);
    os_line = pgrep(pattern:'^firmware-version "', string:cmd_out);
    if (os_line)
    {
      os_line = chomp(os_line);
      var pattern = '^firmware-version "SonicOSX? ((Enhanced |Standard )?[0-9.]+(?:-[a-zA-Z0-9]+)?)';
      match = pregmatch(pattern:pattern, string:os_line);
      if (!isnull(match)) os_name += " " + match[1];
    }

    model_line = pgrep(pattern:'^model "', string:cmd_out);
    if (model_line)
    {
      model_line = chomp(model_line);
      match = pregmatch(pattern:'^model "(.+)"', string:model_line);
      if (!isnull(match)) os_name += " on a SonicWALL " + match[1];
    }
    # Collect time of last reboot.
    if (cmd_out && 'system-uptime "' >< cmd_out)
    {
      foreach line (split(cmd_out, keep:FALSE))
      {
        if (preg(pattern:'^system-uptime "', string:line))
        {
          up_time = line - 'system-uptime "' - '"'; 
          break;
        }
      }
    }
  }
  else
  {
    if (!empty_or_null(cmd_out))
      report_no_command_sw += '\nThe output from "show device" or "show version":\n' + cmd_out;

    # report and exit that sonicwall detected but commands failed to run
    session.close_connection();
    security_report_v4(
      port       : session.port,
      severity   : SECURITY_NOTE,
      extra      : report_no_command_sw
    );
    exit(0);
  }

  # if we reach here sonicwall commands were successful
  set_kb_item(name:"Host/OS/showver", value:os_name);
  set_kb_item(name:"Host/OS/showver/Confidence", value:100);
  set_kb_item(name:"Host/OS/showver/Type", value:"firewall");
  set_kb_item(name:"Host/last_reboot", value:up_time);
  set_kb_item(name:"Host/OS/ratelimited_sonicwall", value:TRUE);
  # set sshlib support level indicating local checks are not available
  set_support_level_na();

  if (strlen(get_preference("SonicWALL SonicOS Compliance Checks[file]:Policy file #1 :")) > 0)
  {
    enable_sonicwall_compliance = TRUE;
    # run commands for compliance checks - will be cached in KB.
    # run "show tech-support-report" command first and cache in KB so
    # other related commands can use that data.
    # This is a very long command output so increasing timeout.
    tech_support_command = "show tech-support-report";
    cmd_out = sh.run_command(channel:channel, command:tech_support_command, raw:TRUE,
                            cmd_timeout_min:90, inactivity_timeout_min:75, sonicwall:TRUE);
    if(check_command_output(data_buf:cmd_out))
    {
      write_compliance_kb_sonicwall(command:tech_support_command ,result:cmd_out);
    }
    else cmd_out = "NA";
    run_sonicwall_commands_compliance(session:session, channel:channel, tsr_result: cmd_out);
  }

  report = "The remote host has has been identified as a SonicWall" + '\n' +
           "device that may be rate limiting SSH connections." + '\n';
  report += "As a result there may be intermittent authentication failures" + '\n' +
            "reported for this device." + '\n\n';

  report += "Although local, credentialed checks for SonicOS are not available," + '\n';
  if(enable_sonicwall_compliance) report_compliance = " and Policy Compliance plugins.";
  else report_compliance = ".";
  report += "Nessus has managed to run commands in support of " + '\n' +
            "OS fingerprinting" + report_compliance + '\n\n';

  report += 'Device information : ' + os_name + '\n';

  timediff = timeofday_diff(start:start_time, end:gettimeofday());
  report += '\nRuntime : ' + timediff + ' seconds\n';

  # close and report
  session.close_connection();
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}

# Junos device
# Note: the only escalation Junos devices support is 'su'.
#       Priv escalation is not supported in this plugin or the legacy ssh library.
#       If we encounter an insufficient priv message, report in plugin output and debug logs.
else if(junos_auth)
{
  priv_error = FALSE;
  report = '\nThe remote host has has been identified as a Juniper Junos' +
           '\ndevice that may be SSH rate limited.\n';
  report += 'As a result there may be intermittent authentication failures' +
            '\nreported for this device.\n';
  # set whether we are in shell or CLI for junos device
  # gather information and set KBs from ssh_get_info.nasl
  var commands_ssh_get_info = make_array(
    'version', 'show version detail',
    'last', 'show chassis routing-engine',
    'config', 'show configuration | display set',
    'interface', 'show interface'
  );
  var cmd_results = make_array();

  if(get_kb_item("Host/Juniper/JUNOS/shell"))
    use_shell_handler_flag = TRUE;
  # run commands to enable local checks
  foreach k (keys(commands_ssh_get_info))
  {
    cmd = commands_ssh_get_info[k];
    raw_cmd = cmd;
    kb = str_replace(string:cmd, find:" ", replace:"_");
    kb = str_replace(string:kb, find:"/", replace:"");
    kb = "Host/Juniper/JUNOS/Config/" + kb;
    cmd += " | no-more";

    cmd = junos_format_cmd(cmd: cmd, flag: use_shell_handler_flag);

    if(use_shell_handler_flag)
      session.dbg_log(message:"running command (shell mode): '" + cmd);
    else
      session.dbg_log(message:"running command (cli mode): '" + cmd);

    output = get_kb_item('flatline/junos_sh_run_command/' + k);
    if(empty_or_null(output))
      output = session.run_command(command:cmd, channel:channel, use_shell_handler:FALSE);
    session.dbg_log(message:"output of " + cmd + ": " + output);   
 
    #output may be different with FIPS mode enabled
    if(k == 'version' && 'Invalid argument' >< output)
    {
      session.dbg_log(message:"command: '" + cmd + " failed with result: '" + output + "'. Retrying with local"); 
      cmd = 'show version local detail | no-more';
      cmd = junos_format_cmd(cmd: cmd, flag: use_shell_handler_flag);
      session.dbg_log(message:"running command: '" + cmd);
      output = get_kb_item('flatline/junos_sh_run_command/fips');
      if(empty_or_null(output))
        output = session.run_command(command:cmd, channel:channel, use_shell_handler:FALSE);
    }
    if("/* ACCESS-DENIED */" >< output)
    {
      session.dbg_log(message:"command: '" + cmd + " failed with result: '" + output + "' due to user privilege error.");
      output = FALSE;
      priv_error = TRUE;
    }
    else if(!check_command_output_junos(data_buf:output))
    {
      session.dbg_log(message:"command: '" + cmd + " failed with result: '" + output + "'");
      output = FALSE;
    }
    if(output)
    {
      set_kb_item(name:"Secret/"+kb, value:output);
      write_compliance_kb_junos(command:raw_cmd, result:output);
    }
    cmd_results[k] = output;
    sleep(1);
  }

  version = cmd_results["version"];
  last = cmd_results["last"];
  config = cmd_results["config"];
  interface = cmd_results["interface"];

  # try to retrieve the list of installed packages
  if(use_shell_handler_flag)
  {
    pkginfo_cmd = "/usr/sbin/pkg_info -a";
    session.dbg_log(message:"running command (shell mode): '" + pkginfo_cmd);
    buf = session.run_command(command: pkginfo_cmd,
                              use_shell_handler: FALSE,
                              channel: channel);
    pkg_info_success = TRUE;

    if (!buf)
    {
      if ("no packages installed" >< session.cmd_error)
        buf = ' ';
      else
      {
        report += 'Command \''+pkginfo_cmd+'\'failed to produce any results.';
        pkg_info_success = FALSE;
      }
    }
    if (pkg_info_success)
    {
      buf = str_replace(find:'\t', replace:"  ", string:buf);
      replace_kb_item(name:"Host/JunOS/pkg_info", value:buf);
    }
  }

  # set showver values if we are in cli mode.
  if(!use_shell_handler_flag)
  {
    # Match "JUNOS Software Release [18.4R2-S7.4]" or "JUNOS EX  Software Suite [18.4R2-S7.4]"
    # or just "Junos: 21.2R3-S3.5" for models like srx1500
    var ver = pregmatch(pattern:"JUNOS\s+(?:EX\s+)?Software\s+(?:Release|Suite)\s+\[([^\]]+)\]", string:version);
    if (isnull(ver))
      ver = pregmatch(pattern:"Junos: (\d[^\s]+)", string:version);

    if (!isnull(ver))
    {
      set_cli_kb_items = TRUE;
      cli_ver = ver[1];
    }
  }

  # Get time of last reboot.
  if (last)
  {
    foreach line (split(last, keep:FALSE))
    {
      match = pregmatch(pattern:"Start time[ \t]+(.+)$", string:line);
      if (match)
      {
        set_last_reboot = TRUE;
        last_reboot_value = match[1];
        break;
      }
    }
  }
  if (config)
  {
    kb = "Secret/Host/Juniper/JUNOS/config/show_configuration_|_display_set";
    replace_kb_item(name:kb, value:config);
  }

  get_junos_mac_addrs(session:session, channel:channel, cmd_result:interface);
  if(version && ("Hostname" >< version || "JUNOS" >< version))
  {
    set_kb_item(name:"Host/Juniper/show_ver", value:version);
    report += '\nLocal security checks have been enabled for Juniper Junos.\n';

    # if local checks are enabled run commands for junos_command_kb_item in junos_kb_cmd_func.inc
    session.dbg_log("Junos local checks are enabled. Running commands used by junos_command_kb_item().");
    run_junos_command_kb_item(session:session, channel: channel, shell:use_shell_handler_flag);
    # set sshlib service level for junos local checks
    sshlib::enable_local_checks();
    set_kb_item(name:"Host/OS/ratelimited_junos", value:TRUE);
  
    if(set_cli_kb_items)
    {
      if(!isnull(cli_ver)) # not really necessary because cli_ver will never be NULL if set_cli_kb_items is true - just being careful.
        replace_kb_item(name:"Host/OS/showver", value:"Juniper Junos Version " + cli_ver);
      replace_kb_item(name:"Host/OS/showver/Confidence", value:100);
      replace_kb_item(name:"Host/OS/showver/Type", value:"embedded");
    }
    if(set_last_reboot)
    {
      replace_kb_item(name:"Host/last_reboot", value:last_reboot_value);
    }
  }
  else
  {
    timediff = timeofday_diff(start:start_time, end:gettimeofday());
    report += '\nJunos device detected, however, some commands failed to run\n' +
              'so local checks are not enabled.\n';
    if(priv_error)
      report += '\nAuthentication successful, however, some commands' +
                '\nfailed to run due to insufficient user privileges.\n';
    report += '\nRuntime : ' + timediff + ' seconds\n';
    session.close_connection();
    security_report_v4(
      port       : session.port,
      severity   : SECURITY_NOTE,
      extra      : report
      );
    exit(0);
  }

  if(priv_error)
  {
    report += '\nAuthentication successful and local checks enabled, however, some' +
              '\ncommands failed to run due to insufficient user privileges.\n';
  }
  timediff = timeofday_diff(start:start_time, end:gettimeofday());
  report += '\nRuntime : ' + timediff + ' seconds\n';

  # close and report
  session.close_connection();
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}

#Alcatel-Lucent OmniSwitch
else if(omniswitch_auth)
{
  report = '\nThe remote host has been identified as an Alcatel-Lucent' +
           '\nOmniSwitch device that may be SSH rate limited.\n';
  report += 'As a result there may be intermittent authentication failures' +
            '\nreported for this device.\n';

  timediff = timeofday_diff(start:start_time, end:gettimeofday());
  report += '\nRuntime : ' + timediff + ' seconds\n';

  cmd = "show microcode";

  session.dbg_log(message:"running command: " + serialize(cmd));

  flatline = get_kb_item("flatline/TEST");
  output = get_kb_item('flatline/omniswitch_sh_run_command/show_microcode');
  if(isnull(flatline) && empty_or_null(output))
    output = sh.run_command(command:cmd, channel:channel, cmd_timeout_min:60, raw:TRUE);
  session.dbg_log(message:"output of " + serialize(cmd) + ": " + serialize(output));

  if(output =~ "Package\s*Release\s*Size\s*Description")
  {
    report += '\nLocal checks have been enabled for an Alcatel-Lucent OmniSwitch.\n';
    report += '\nOS Security Patch Assessment is not supported for Alcatel-Lucent OmniSwitch devices.\n';
    set_kb_item(name:"Host/AOS/show_microcode", value:output);
    set_kb_item(name:"Host/OS/ratelimited_omniswitch", value:TRUE);
  }
  else
  {
    session.dbg_log(message:"command: '" + cmd + " failed with result: " + serialize(session.cmd_error) + ".");
    report += 'However, running ' + serialize(cmd) + ' failed to produce expected results.';
  }

  # close and report
  if(isnull(flatline))
    sh.run_command(command:"exit", channel:channel, cmd_timeout_min:60, raw:TRUE);

  session.close_connection();
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}
else
{
  # should not reach
  session.close_connection();
  exit(0,"Unable to determine if remote host is a rate limited device.");
}

