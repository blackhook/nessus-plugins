#TRUSTED 3343d8b8c0045aac477135c38378a779ed32aa2bcb60c28f0890c6dda8c9f17997af085add62b1d7e881f6c272b5a350e87f17b45a34f0529d543ec4eb2b78fc65350a2ab7a97ea68b9eeec11ee827835508aa2353e0b55f49c5e3e6edaadcb4f6be56411465375ff3881bea57b49e6d4afe2bfc22ce94a855b7b7b846583ab4574a69aeb8627b79e282cf48e1da3af42c6ec6768a7fbbb5e8dc4ff8dc78b616a7b94d4f5f0a4c3719def4fcaca58b3046af21a0334327242f91caa8ec654bdcb6c2c396bb0c52106c02c161f01117106f9c1c5b9c0ec5e5adfad473bdc023411b7daf74a5f299e80d9cd1f5cd49e1717549befbf8bacbd7f1983c6ef44dec758129c55df262e564ec9ce38be5af5162adffbf54ed9b2cb7831bb94dc373b662727e734d13951b5a7a610ecc8298f0138121da1575e8a144824ef79ec9a8dd26fad348ee986cd03b876056a01d2a108c6a5124d05635e23daed79ae7cb330fe7b61ac27846b19fcca4a70fd28f2a1c532950069007f52dcf5808e1ac8ebe3a4e80607280fc89f9a3cdb866a4cf4a64a721349a3d9993a7d0da74ceb1d935241ef2268e3609cf08ddb4c6efbfa8e08fad698149da46dfa28f8015d0f16e91b94a2edca54b66e9297394aec489967f0b2e50d01ee26084a4c31f8a6f6025744420ecfb1fbef9df401c1a77d3f771449b295c669175bd4cea4f710702f6b8df92b5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78067);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2014-6277", "CVE-2014-6278");
  script_bugtraq_id(70165, 70166);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34860");

  script_name(english:"Bash Remote Code Execution (CVE-2014-6277 / CVE-2014-6278) (Shellshock)");
  script_summary(english:"Logs in with SSH.");

  script_set_attribute(attribute:"synopsis", value:
"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker could remotely execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2014/Oct/9");
  # http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40f2f5a");
  script_set_attribute(attribute:"solution", value:
"Update Bash.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6277");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function report_and_exit(port, command, output, patch_check)
{
  local_var hdr, report;

  report = NULL;
  if (report_verbosity > 0)
  {
    hdr =
    '\n' + 'Nessus was able to login via SSH and run the following command :' +
    '\n' +
    '\n' + command;

    report =
      hdr  +
      '\n' +
      '\n' + 'and read the output :' +
      '\n' +
      '\n' + output +
      '\n';

    if(patch_check)
    {
      report +=
        'This indicates that the patch for CVE-2014-6277 and ' +
        '\n' + 'CVE-2014-6278 is not installed.';
    }

  }
  security_hole(port:port, extra:report);
  exit(0);
}


if ( islocalhost() )
{
 info_t = INFO_LOCAL;
}
else
{
 ret = ssh_open_connection();
 if ( !ret ) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
 info_t = INFO_SSH;
 if(info_t == INFO_SSH) ssh_close_connection();
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

ret = ssh_open_connection();
if ( !ret ) audit(AUDIT_FN_FAIL, 'ssh_open_connection');

# Check CVE-2014-6277
#
# - We check CVE-2014-6277 first because this CVE covers some older
#   bash versions while CVE-2014-6278 doesn't, according to
#   http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html.
#
# - The CVE-2014-6277 PoC produces a segfault.

command = 'E="() { x() { _; }; x() { _; } <<A; }"' + ' bash -c E';
output = ssh_cmd(cmd:command, noexec:TRUE);

if( "egmentation fault" >< output
 || "egmentation Fault" >< output) # Solaris
{
  if(info_t == INFO_SSH) ssh_close_connection();
  report_and_exit(port:port, command: command, output: output);
}

# Problem reported on AIX 6.1 TL 8 SP 1 with bash 4.3.7 (redmine 10989)
# Disable CVE-2014-6278 check for now

# CVE-2014-6277 detection fails, try to detect CVE-2014-6278,
# This CVE appears to work against bash 4.2 and 4.3.,
# but not against 4.1 or below.
#
#test_command = "echo Plugin output: $((1+1))";
#command = "E='() { _; } >_[$($())] { " + test_command + "; }' bash -c E";
#output = ssh_cmd(cmd:command);

#if ("Plugin output: 2" >< output) vuln_6278 = TRUE;

# ok we detected CVE-2014-6278, send another command
# hoping to get a more convincing output
#if(vuln_6278)
#{
#  test_command = "/usr/bin/id";
#  command2 = "E='() { _; } >_[$($())] { " + test_command + "; }' bash -c E";
#  output2 = ssh_cmd(cmd:command2);
#  if (output2 =~ "uid=[0-9]+.*gid=[0-9]+.*")
#  {
#    command = command2;
#    output  = output2;
#  }
#  report_and_exit(port:port, command:command, output:output);
#}

# If we still cannot detect CVE-2014-6277 or CVE-2014-6278,
# we try to determine if the patch for these CVEs has been applied.
command = "E='() { echo not patched; }' bash -c E";
output = ssh_cmd(cmd:command);
if(info_t == INFO_SSH) ssh_close_connection();

# Patch not installed
# Ignore cases where the host returns an "unknown command" error and returns the entire command
if (("not patched" >< output) && ("echo not patched" >!< output))
  report_and_exit(port:port, command:command, output:output, patch_check:TRUE);
# Patch installed
else audit(AUDIT_HOST_NOT, "affected.");


