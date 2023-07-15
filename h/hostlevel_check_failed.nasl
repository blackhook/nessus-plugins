#TRUSTED 04e4014107f8a5844d8b14ed1ea7a3b0a2e614aaebf2b0294ec5ea1952b3b87d769d8bf4004f6e5454dbdea722f1bca4f62482dcb0e967846e6f0ae6ed7b345b39b0ae771e412c71586f2e2b880ce1424560fe8f09f9f65ffc846ad439f22eab55bb36813398a312ba11d7ad835851ed8b0cf8cbd36adb08d9502029efd731ac1e22349807940d1ac4375ddd97aac23e763b5b45292759836fd8ebb134f6970d6710fd7ce1b431000d444a6d682ab8c5e5866d82ebaa51fbbcefc2179842370c0ef307176c5e09af6bd463bf5c33245e3db5547cd3c8d71afc5a3780156a0e0dd54341bcb4b8bd6b315081d1778c1cfb3592fc2b6fdeea50bf99c0e45a0ad36deac46bf432ea4a9595c21d0c673a94111129a2fe8bbc15cc2ce8c85f8d554625d3aa312f1378dc504456df711f5c193fe24376a29eb43de01f42bbdc5226bc63afb3fe4caba8320905a89a2f21190309b9a48fc6d7b7fc3bea60eede2474a649a0cc90abd82579a6661b303caa7e7160341e129700ff6d4e652981c71854b38c3c47413b3824710919c2ab0674496ec4ac79925f6946eaa292f1f45a62fa42316d857f04da55bbcb1bdf40186a6ad31e03cc84422555fa40c791aee77cb6d049561af2bd42a59e81eca1038fc05ab611c843f32d51858584880bbbe224d3bde7becca19fe8c7b07b8bdde98264658e9bb447bde745bf6e653d3ea8eec2ddadb5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21745);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/12");

  script_xref(name:"IAVB", value:"0001-B-0501");

 script_name(english:"OS Security Patch Assessment Failed");
 script_summary(english:"Displays information about the scan");

 script_set_attribute(attribute:"synopsis", value:"Errors prevented OS Security Patch Assessment.");
 script_set_attribute(attribute:"description", value:
"OS Security Patch Assessment is not available for this host because
either the credentials supplied in the scan policy did not allow
Nessus to log into it or some other problem occurred.");
 script_set_attribute(attribute:"solution", value:
"Fix the problem(s) so that OS Security Patch Assessment is possible.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_END2);
 script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Settings");

 script_dependencies("local_checks_enabled.nasl");
 exit(0);
}


include("smb_func.inc");
include("lcx.inc");

function check_svc(svc, port_name, default)
{
  var port, soc;
  var ret, os, os_confidence, err;

  if (lcx::get_issue_count(type:lcx::ISSUES_SVC) == 0 &&
      svc != lcx::PROTO_SMB)
    return NULL;

  var issues = lcx::get_issues(type:lcx::ISSUES_SVC, proto:svc);
  if (max_index(issues) > 0)
  {
    if (!isnull(port_name))
    port = get_kb_item(port_name);

    # First check that a socket can be opened
    if (!port) port = default;
    if (!get_port_state(port)) return NULL;
    if (!lcx::TESTING)
    {
      soc = open_sock_tcp(port);
      if (!soc) return NULL;
      close(soc);
    }

    var lines;
    foreach var issue (issues)
    {
      ret +=
        '\n  - Plugin      : ' + issue['plugin'];
      if (issue['plugin_id']) ret +=
        '\n    Plugin ID   : ' + issue['plugin_id'];
      if (issue['plugin_name']) ret +=
        '\n    Plugin Name : ' + issue['plugin_name'];
      if (issue['proto_name']) ret +=
        '\n    Protocol    : ' + issue['proto_name'];
      ret +=
        '\n    Message     : ';
      # If message is more than one line or would exceed 70 chars with
      # the label field, add a newline
      lines = split(issue['text']);
      if (max_index(lines) > 1 || strlen(lines[0]) > (70 - 18))
        ret += '\n';
      ret += issue['text'] + '\n';
    }
    return ret;
  }

  # If no SMB service errors have been logged, but SMB login failed,
  # check for SMB port socket errors
  if ( svc == lcx::PROTO_SMB && !get_kb_item("Host/local_checks_enabled")
       && get_kb_item("SMB/login_filled/0") )
  {
    #
    # https://discussions.nessus.org/message/11795#11795
    # For Windows systems, if credentials have been supplied we should
    # warn that we could not log in, even if port 139/445 is unreachable.
    #
    # - If it's Windows
    # - And we're sure of it
    # - And no SMB/login key is present (yet SMB/login_filled/0 was set)
    # - Then do an alert
    #
    os = get_kb_item("Host/OS");
    os_confidence = get_kb_item("Host/OS/Confidence");
    if ( isnull(os) || os_confidence <= 65 || "Windows" >!< os ||
         !isnull(get_kb_item("SMB/login")) )
      return NULL;

    # Let's try to find out why we could not connect
    if (defined_func("socket_get_error") && !lcx::TESTING)
    {
      port = default;
      soc = open_sock_tcp(port, nonblocking:TRUE);
      if (soc)
      {
        while ( socket_ready(soc) == 0 ) usleep(50000);
        err = socket_get_error(soc);
        close(soc);
      }
      if ( !soc ) err = "(unable to create a socket)";
      else if ( err == ETIMEDOUT ) err = "(connection timed out)";
      else if ( err == EUNREACH ) err = "(service is unreachable)";
      else if ( err == ECONNREFUSED ) err = "(port closed)";
      else err = "(protocol failed)";
    }
    else err = "(could not contact service)";

    ret = '  - It was not possible to log into the remote host ' +
      'via smb ' + err + '.\n';
    return ret;
  }
}

report = "";

# Check for logged local checks failures
if (lcx::get_issue_count(type:lcx::ISSUES_ERROR) > 0)
{
  errs = lcx::get_issues(type:lcx::ISSUES_ERROR);
  report += '\nOS Security Patch Assessment failed because :\n';
  foreach err (errs)
  {
    report +=
      '\n  - Plugin      : ' + err['plugin'];
    if (err['plugin_id']) report +=
      '\n    Plugin ID   : ' + err['plugin_id'];
    if (err['plugin_name']) report +=
      '\n    Plugin Name : ' + err['plugin_name'];
    if (err['proto_name']) report +=
      '\n    Protocol    : ' + err['proto_name'];
    report +=
      '\n    Message     : ';
    # If message is more than one line or would exceed 70 chars with
    # the label field, add a newline
    lines = split(err['text']);
    if (max_index(lines) > 1 || strlen(lines[0]) > (70 - 18))
      report += '\n';
    report += err['text'] + '\n';
  }
}

# If OS Security Patch Assessment is available and no failures to report, exit
if (get_kb_item("HostLevelChecks/local_security_checks_enabled") && !report)
  exit(0, "OS Security Patch Assessment is available.");

# Check services for login failures
info = "";
info += check_svc(svc:lcx::PROTO_SSH, default:22);
info += check_svc(svc:lcx::PROTO_TELNET, port_name:"Services/telnet",
  default:23);
info += check_svc(svc:lcx::PROTO_REXEC, port_name:"Services/rexec",
  default:513);
info += check_svc(svc:lcx::PROTO_RLOGIN, port_name:"Services/rlogin",
  default:513);
info += check_svc(svc:lcx::PROTO_RSH, port_name:"Services/rsh",
  default:514);
info += check_svc(svc:lcx::PROTO_SMB, default:kb_smb_transport());

if (info) report +=
    '\nThe following service errors were logged :\n' + info;

if (report)
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
else
{
  if (lcx::svc_available()) exit(0, "No logged failures to report.");
  else exit(0, "No local checks ports or services were detected.");
}
