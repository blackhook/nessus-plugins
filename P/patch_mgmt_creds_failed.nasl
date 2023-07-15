#TRUSTED 6392a988e602182d599bf64c3174fe41fb617ca79403b436e82fda20d27263c49d2f5993204533e1a099f6a7d9ada6799155db822bd97d4c46b688fac74ed0428346aebbb5f10fb3d795f4eae1cbb5bde35e5c8b4f19fb77beebe634cec20b34ce72448d500e22cc96fce9344afc4470711d74aa6c821c5b7f87203320ab99333c9f749901d75f441a2ffdf6ffee42f1ff41d617b815c55e81e43a16d9cc23c46235997e2da93dd0298d3e8248f15eef7543c52f954d05265316d3640d3bbf58435a5e999c194b710daa333beb23a8e356d7e2ffb1bc5225cb577ce304932f5e15ffae94b415bc28a04a8e69caf20530e25c48452283fff8cd3cf740445e4a75aae927670afe9bb40a2c597393ca43aad168577261bb493d4b610934e98f0501a04f2c5489f710f4d72b89ad89b31f18d476ce66e228a9bace192cb52705c6a7dce7cac248204ec29c6342161367e583432db57d476102f13cdc93e9a8a1c158d37366c459155e82ed29e0a60edeb35e14ecd8fc5551dcbe4c403054ce6a4623a0474d9fa194670266481ce15129c5b1e558f42cf1873a2d7a235e10a0c8a85ec297cb68aa6cf3852e3104b42bb0821124a70aaac4680ed431fa3a6e44aa27c98e75e4afdc3fdb0e2eb75b5a8e7ef27fcaad981ac9876b905982a788980ec75d6cef8cfacbb85dfaf12081a73594d93c157deb9f8a450ba4578adc51cc4b71c2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122503);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_name(english:"Integration Credential Status by Authentication Protocol - Failure for Provided Credentials");
  script_summary(english:"Reports patch management authentication failure details for the scan.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was unable to log into the designated patch management system
using the provided credentials, in order to gather information about
this host.");
  script_set_attribute(attribute:"description", value:
"Nessus was not able to execute patch management checks because it
was not possible to log into the designated patch management
system using the credentials that have been provided.");
  script_set_attribute(attribute:"solution", value:
"Address the reported problem(s) so that credentialed patch
management checks can be executed.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("lcx.inc");

function report_failures(prefix, proto, port)
{
  if (isnull(proto)) return 0;

  var kb_prefix = prefix + proto + "/" + port;
  if (get_kb_list(kb_prefix+"/Success")) return 0;

  var users = lcx::get_users_with_issues(type:lcx::PM_ISSUES_AUTH,
    port:port, proto:lcx::PROTO_GLOBALS[proto]);

  if (isnull(users) || max_index(users) < 1) return 0;

  var report =
    '\n  Protocol        : ' + proto +
    '\n  Port            : ' + port +
    '\n  Failure details :\n';

  var issues, lines, check, reported, num_reported=0;
  var host = '';
  var product = '';

  foreach var user (users)
  {
    report += '\n  - User : ' + user;
    issues = lcx::get_issues(type:lcx::PM_ISSUES_AUTH, port:port,
      user:user, proto:lcx::PROTO_GLOBALS[proto]);

    reported = "|";
    foreach var issue (issues)
    {
      check = issue['plugin'] + ":" + issue['text'] + "|";
      if ("|" + check >< reported) continue;
      reported += check;

      if (num_reported == 0)
      {
        host = issue['host'];
        product = issue['pm_prod'];
      }

      report += '\n' +
        '\n    - Plugin      : ' + issue['plugin'];
      if (issue['plugin_id']) report +=
        '\n      Plugin ID   : ' + issue['plugin_id'];
      if (issue['plugin_name']) report +=
        '\n      Plugin Name : ' + issue['plugin_name'];
      report +=
        '\n      Message     : ';
      # If message is more than one line or would exceed 70 chars with
      # the label field, add a newline
      lines = split(issue['text']);
      if (max_index(lines) > 1 || strlen(lines[0]) > (70 - 20))
        report += '\n';
      report += issue['text'] + '\n';
      num_reported++;
    }
  }

  if (num_reported > 0)
  {
    report =
      '\nNessus was unable to log into the ' + product + ' patch management' +
      '\nsystem hosted on ' + host +
      '\nfor which credentials have been provided :\n' + report;

    security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  }

  return num_reported;
}

failures = get_kb_list("PManage/Auth/*/Failure");

pm_ports = make_list();
db_ports = make_list();

pat = "^PManage/Auth/([A-Za-z]+/[0-9]+)/.*";
foreach fail (keys(failures))
{
  match = pregmatch(pattern:pat, string:fail, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];
  pm_ports = make_list(pm_ports, protoport);
}

var num_reported = 0;
var tmp;

if (!empty(pm_ports))
{
  foreach p (list_uniq(pm_ports))
  {
    tmp = split(p, sep:'/', keep:FALSE);
    num_reported += report_failures(prefix:"PManage/Auth/", proto:tmp[0], port:tmp[1]);
  }
}

# failures reported in kb, but success as well. no need to report failures
if (num_reported == 0)
  exit(0, "No patch management authentication failures with user supplied credentials to report.");

