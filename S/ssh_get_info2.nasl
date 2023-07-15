#TRUSTED 25ead9f8739086f5667df047fc4fd0805b19b9b58da1fa7b1464ec94537e3f78c482aec3408723394dfdfdb60d22f71112263eb3beddff721a3826b5eb4d11bcaa5e523a1a340834dab3757b5778e661beb4e8e77c27ae9931333df25ae18fd9be0b1797e36cc00f2b3913f88e2ded07f573634a09cc71c4d98c985476145d1a937de1b14b092fd87f2c75ba696c896f8cdf210aed1b9e7eaa04dc6c6e326874e9911164339a3fa43142f92c3428e74befbc06e1c61085e1123a1f5f355952498eaabdb968afb127773e133fcf31eeac45033df3c8d25172642a948ab7cb5664f406be9a897e4e8ddc4bda404bb15ca0945175a07db065731d83d37f7d5992e1fe0536db9c1915f7dc60ea156770cb75ba9694129466ad52e353f7d5eae0567892c0e800a3637d3f01d2fd147c69c2582cd7a88abccb2823eff1fc1a186390c58b298cea558f1664477d38adee6da1d8f77ea92737b98692da1193ae043e1ca4fc018d6a0caf37d6021b5b8263d6b8503b8d69ccb55c91add870083e8fa8614c5abd24fde5a31cf3a8767dfbdaabf6092d77a77b6e0cc68c03cc13b8cbba467411073766b9ca10640c5492acf716a2fa7505bc946a0918d54a8a22508285c32f918f65552fbe00b564b701b151bc2d50e19a41633a8d851c92b0362e16c474f5d6f1ead58cf124808c6cbff0847c4bf592494e66ded44c326ae8bc962758c860
#TRUST-RSA-SHA256 7b3f1d1701e3a343110e27fd242f8973d9b93b348c0be1ff10a8d242d6f4287e73a2bbea98429c0ebabae8edae3e69386436a4b46385beb79ed386b6a4df35fd8c07cec7dbdaaaf53f702948bbed1b353e88022bceaaad86dfa6d7631084ad674fb5da80ae49da4bb7c759f4ab80e44bf2cee7f70938e9b48b9b9a086b1f1e2de5f0715ed3b6392c16ddfa2b3a47ab35e3ba848b34d62587f5fcdf294e71904d63cf067b5c26b64cc776831838022a3d8e21c69dbbdebb1463560fabbebacf7b2d5fb2330f32026031e39657b98399426acbba2ffc1fa000d2015948b9fd1d954e093ec6c2aa4087e7996993f4f393309d1b1cfc1324299b40ec01a28509ccc89fa892e2c312797d43c2009944165f9b2dd390bf233801c0b1dc67f0dc42f74250dadbe47577ba37261f30ae30daad78215c4653cbfb70c19e06cf2528966bea706945c93108b9f248810c568d19b5008d465cb9f114ab1c7f01104ebcc356ef96c2fde4bd1db497cb536e92b1f823b041a88a2d8361c7dc14d6ae605601366f6e964d712f04fb69a7b4890465fd4132372d7e241d1e9335466ed000b5b9d22936298af3faf2b31417fd0ba12a5dc59c54684a67cc3b05c9313f01ad496a05f41a01985babe3cc6ff36dc9b6b4d37d2d46bed47f839a8db1c647deb57ef1043a8d1d2cbbcfeb429a7e5a73ff07a883783c4b43e49f1bb9d01cd027c635f47048
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97993);
  script_version("1.50");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_name(english:"OS Identification and Installed Software Enumeration over SSH v2 (Using New SSH Library)");
  script_summary(english:"Gathers OS and installed software information over SSH.");

  script_set_attribute(attribute:"synopsis", value:
"Information about the remote host can be disclosed via an
authenticated session.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote host using SSH or local
commands and extract the list of installed packages.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_settings.nasl", "clrtxt_proto_settings.nasl", "ssh_check_compression.nasl");
  if (defined_func("xmlparse")) script_dependencies("satellite_settings.nbin", "vmware_installed_patches.nbin", "vmware_installed_vibs.nbin");

  script_timeout(20*60);
  exit(0);
}

include("global_settings.inc");

include("datetime.inc");
include("string.inc");
include("byte_func.inc");
include("misc_func.inc");

include("ssh_get_info2.inc");
include("ssh_func.inc");
include("ssh_lib.inc");

include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("lcx.inc");

USE_SSH_WRAPPERS = TRUE;

start_time = gettimeofday();

# sleep for IOS-XR
sleep(1);
enable_ssh_wrappers();

use_hostlevel = FALSE;
proto = NULL;
port = NULL;
user = NULL;

if (check_for_alternate_data_sources())
{
  security_note(port:0, extra:report);
  exit(0);
}

if(try_local_login())
{
  use_hostlevel = TRUE;
  proto = lcx::PROTO_LOCAL;
  report = '\nNessus can run commands on localhost to check if patches are applied.\n';
}
else
{
  # Check first to see if any credentials have been supplied
  if (
    !empty_or_null(get_kb_item("Secret/SSH/password")) ||
    !empty_or_null(get_kb_item("Secret/SSH/kdc_hostname")) ||
    !empty_or_null(get_kb_item("Secret/SSH/privatekey"))
  ) ssh_supplied = TRUE;

  if (!empty_or_null(get_kb_item("Secret/ClearTextAuth/login")))
    clrtxt_supplied = TRUE;

  if (!ssh_supplied && !clrtxt_supplied)
    exit(0, "No SSH or cleartext credentials were supplied.");

  if(!empty_or_null(get_kb_item("SSH/disallowed_login_id")))
  {
    disallowed_login = TRUE;
    disallowed_login_error = NULL;
    disallowed_login_errors = get_kb_list(sshlib::SSH_LIB_KB_PREFIX + 'disallowed_login_id/error');
    if (!empty_or_null(disallowed_login_errors))
    {
      error_list = make_list(disallowed_login_errors);
      disallowed_login_error = '  - ' + join(error_list, sep:'\n  - ');
    }
  }

  login_res = FALSE;
  if (ssh_supplied)
  {
    # Remove any previous try_ssh_kb_settings_login() failure so login
    # will be tried again
    prev_fail_kb = sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed";
    if (get_kb_item(prev_fail_kb))
    {
      spad_log(message:"try_ssh_kb_settings_login() previously failed. "+
        "Removing failure and trying again.");
      rm_kb_item(name:prev_fail_kb);
    }

    session = new("sshlib::session");
    login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:FALSE);
    sleep(1);
  }

  if(!login_res)
  {
    use_hostlevel = FALSE;
    if (clrtxt_supplied)
    {
      #    not implemented in hostlevel_funcs.inc
      #    login_method = "RLOGIN";
      #    use_hostlevel = try_rlogin();

      login_method = "RSH";
      proto = lcx::PROTO_RSH;
      use_hostlevel = try_rsh_login();

      if(!use_hostlevel)
      {
        login_method = "REXEC";
        proto = lcx::PROTO_REXEC;
        use_hostlevel = try_rexec_login();
      }

      if(!use_hostlevel)
      {
        login_method = "TELNET";
        proto = lcx::PROTO_TELNET;
        use_hostlevel = try_telnet_login();
      }
    }

    if(!use_hostlevel && disallowed_login)
    {
      timediff = timeofday_diff(start:start_time, end:gettimeofday());
      exit_message = 'The host requested that login be performed ' +
        'as a different user:\n' + disallowed_login_error;
      lcx::log_issue(type:lcx::ISSUES_SVC, msg:exit_message,
        proto:lcx::PROTO_SSH, port:session.port);
      if(typeof(session) == 'object') session.close_connection();
      exit(1, exit_message + '\nRuntime : ' + timediff + ' seconds.');
    }
    else if(!use_hostlevel)
    {
      timediff = timeofday_diff(start:start_time, end:gettimeofday());
      port = session.port;
      if(typeof(session) == 'object') session.close_connection();
      exit_message = 'Unable to login to remote host with supplied credential sets.';
      try_kb_login_errors = get_kb_list(sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login/error");
      if (!empty_or_null(try_kb_login_errors))
      {
        error_list = make_list(try_kb_login_errors);
        exit_message += '\nErrors:\n  - ';
        exit_message += join(error_list, sep:'\n  - ');
      }
      if (
        "password" >< exit_message &&
        "must be changed" >< exit_message
      )
      {
        lcx::log_issue(type:lcx::ISSUES_ERROR, msg:exit_message,
          proto:lcx::PROTO_SSH, port:port);
      }
      else
      {
        lcx::log_issue(type:lcx::ISSUES_SVC, msg:exit_message,
          proto:lcx::PROTO_SSH, port:port);
      }
      exit_message += '\nRuntime : ' + timediff + ' seconds.';
      exit(1, exit_message);
    }

    report = '\nIt was possible to log into the remote host via ' + login_method + '.\n';
    port = port_g;
    user = login;
    lcx::log_auth_success(proto:proto, port:port, user:user,
      clear_failures:TRUE);
  }
  else
  {
    # Gather / report session variables before closing session
    report = '\nIt was possible to log into the remote host via SSH using \''
      + session.login_method + '\' authentication.\n';

    rm_kb_item(name:"Host/Auth/SSH/" + session.port + "/Failure");
    report_xml_tag(tag:"ssh-auth-meth", value:session.login_method);

    proto = lcx::PROTO_SSH;
    port  = session.port;
    user  = session.user;

    host_info_key_val['remote_ssh_banner'] = session.remote_version;
    host_info_key_val['remote_ssh_userauth_banner'] = session.userauth_banner;
    host_info_key_val['kb_connection_id'] = session.get_kb_connection_id();

    escl_method = get_kb_item(sshlib::SSH_LIB_KB_PREFIX +
      host_info_key_val['kb_connection_id'] + "/escalation_type");
    cred_type = get_kb_item(sshlib::SSH_LIB_KB_PREFIX +
      host_info_key_val['kb_connection_id'] + "/cred_type");
    auth_method = get_kb_item(sshlib::SSH_LIB_KB_PREFIX +
      host_info_key_val['kb_connection_id'] + "/login_method");
    session.close_connection();

    if(disallowed_login)
      report +=
        '\nNote, an attempt was made to log in with a different credential set in' +
        '\nthe policy but the host returned an error : ' +
        '\n' + strip(disallowed_login_error) + '\n';

    set_kb_item(name:'HostLevelChecks/proto', value:'ssh');
    report_xml_tag(tag:"local-checks-proto", value:"ssh");

    set_kb_item(name:"HostLevelChecks/login", value:user);
    report_xml_tag(tag:"ssh-login-used", value:user);

    if(!isnull(cred_type))
      replace_kb_item(name:"HostLevelChecks/cred_type", value:cred_type);
    if(!isnull(auth_method))
      replace_kb_item(name:"HostLevelChecks/auth_method", value:auth_method);

    if(get_kb_item("global_settings/enable_plugin_debugging"))
      SSH_DEBUG = TRUE;

    sshlib::set_support_level(level: sshlib::SSH_LIB_SUPPORTS_LOGIN);

    if(SSH_DEBUG)
      spad_log(message:'Login success! Associated escalation method to try: ' + escl_method + '\n');

    exec_tried = FALSE;
    if(!escl_method || "Nothing" >< escl_method)
    {
      spad_log(message:'Exec_checks: ' + obj_rep(exec_checks) + '\n');

      ret = sshlib::try_ssh_exec(port:port, cmd_list:exec_checks);

      exec_tried = TRUE;
      if(ret[0])
      {
        if(SSH_DEBUG)
          spad_log(message:'Using exec to run commands.\n');
      }
      else
      {
        if(SSH_DEBUG)
          spad_log(message:'try_ssh_exec() : ' + ret[1]);
      }
    }
    if(sshlib::get_support_level() < sshlib::SSH_LIB_SUPPORTS_COMMANDS)
    {
       report_backup1 = report;

       ret = sshlib::try_ssh_shell_handlers(port:port, shell_handlers:handler_list, cmd_list:shell_handler_checks);
       if(ret[0])
       {
         if(SSH_DEBUG)
         {
           spad_log(message:'Found working shell handler: ' + get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "shell_handler") + '.\n');
         }

         if("command was successful without privilege escalation" >< ret[1])
         {
           report_backup2 = report;
           report = report_backup1;

           seperator = '\n';
           additional_info = " an unknown reason. ";
           if(!isnull(ret[2]) && strlen(ret[2]) > 0)
           {
             additional_info = ' the following reason :\n\n' + ret[2] + '\n\n';
             seperator = " ";
           }

           # see if exec would work
           ret = sshlib::try_ssh_exec(port:port, cmd_list:exec_checks);
           if(ret[0])
             rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "shell_handler");
           else
             report = report_backup2;

           # Last use of escl_method in this plugin and only used for reporting, safe to modify.
           if (escl_method == "su_sudo")
             escl_method = "su+sudo";
           report += '\n' + "Note, though, that an attempt to elevate privileges using '" + escl_method + '\' failed\n' +
                     'for' + additional_info + 'Further commands will be run as the user' + seperator + 'specified in the scan policy.\n';
         }
         else
         {
           if(!isnull(escl_method))
              replace_kb_item(name:"HostLevelChecks/escl_method", value:escl_method);
         }
       }
       else
       {
         if(SSH_DEBUG)
           spad_log(message:'try_ssh_shell_handlers() : ' + ret[1]);
      }
    }
    if(sshlib::get_support_level() < sshlib::SSH_LIB_SUPPORTS_COMMANDS
       && !exec_tried)
    {
      ret = sshlib::try_ssh_exec(port:port, cmd_list:exec_checks);
      exec_tried = TRUE;
      if(ret[0])
      {
        if(SSH_DEBUG)
          spad_log(message:'Using exec to run commands.\n');
        report += '\n' +
          "Note, though, that an attempt to elevate privileges using '" +
          escl_method + '\' failed\n' +
          'because a compatible shell handler was not found. Further commands\n' +
          'will be run as the user specified in the scan policy.\n';
        rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX +
          host_info_key_val['kb_connection_id'] + "/escalation_type");
      }
      else
      {
        if(SSH_DEBUG)
          spad_log(message:'try_ssh_exec() : ' + ret[1]);
      }
    }
  }
}

if(typeof(session) == 'object') session.close_connection();

local_checks_hostlevel = FALSE;
if(use_hostlevel)
{
  if(info_t == INFO_LOCAL)
    ret = try_hostlevel(cmd_list:local_scanner_checks);
  else
    ret = try_hostlevel(cmd_list:hostlevel_checks);

  if(ret[0])
  {
    if (get_kb_item("Host/local_checks_enabled"))
    {
      local_checks_hostlevel = TRUE;
      set_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "local_checks_hostlevel",
                  value:TRUE);
    }
    if(SSH_DEBUG)
    {
      spad_log(message:'Found working shell handler: ' + get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "/shell_handler") + '_shell_handler.\n');
    }
  }
  else
  {
    if(SSH_DEBUG)
      spad_log(message:'try_hostlevel() : ' + ret[1]);
  }
}

if(failure_kb_msg)
{
  if (!failure_kb_type) failure_kb_type = lcx::ISSUES_ERROR;
  lcx::log_issue(type:failure_kb_type, msg:failure_kb_msg,
    proto:proto, port:port, user:user);
}

if(sshlib::HOST_SUPPORT_LEVEL != sshlib::HOST_SUPPORTS_LOCAL_CHECKS &&
   !local_checks_hostlevel)
{
  failure_type = NULL;
  switch (sshlib::HOST_SUPPORT_LEVEL)
  {
    case sshlib::HOST_LOCAL_CHECKS_UNAVAILABLE:
      set_kb_item(name:"HostLevelChecks/unavailable", value:SCRIPT_NAME);
      failure_msg =
        'We are able to identify the remote host.'+
        '\nOS security patch assessment is NOT supported.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
      break;
    case sshlib::HOST_LOCAL_CHECKS_ERROR:
      failure_msg =
        'We are able to identify the remote host, but encountered an error.'+
        '\nOS Security Patch Assessment is NOT available.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_ERROR;
      break;
    case sshlib::HOST_SUPPORTS_COMMANDS:
      failure_msg =
        'We are able to run commands on the remote host, but are unable to'+
        '\ncurrently identify it in this plugin.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
      break;
    case sshlib::HOST_SUPPORTS_LOGIN:
      failure_msg =
        'The remote host is not currently supported by this plugin.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
      break;
    default:
      # should not be possible to get this far, but handle just in case
      failure_msg = 'Unable to run commands on the remote host.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
  }

  if(!failure_kb_msg && failure_msg)
    lcx::log_issue(type:failure_type, msg:failure_msg, proto:proto,
      port:port, user:user);
}

timediff = timeofday_diff(start:start_time, end:gettimeofday());
report += '\nRuntime : ' + timediff + ' seconds\n';
lcx::log_report(text:report);
security_note(port:0, extra:report);
exit(0);
