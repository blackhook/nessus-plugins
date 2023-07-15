#TRUSTED 32761162e000228c3ac0b803b3d43fb2cc8bb13f759cf1108effaacdd8b6709b5271f2b3df9947612b9b38d277d2ca17859c5908b189a59591a87f9127c3274a2950eb05a79f5d64bfe2162b4cabecf62580a2d904217c2d55afb2d152b6702f1274897372f7d8763f3789f6a3363a2d272adf5555a830d34f76f772e099ed69c4c96e3ab46500290b1611f47d21f5e2f867684c9100920ee1abfa663c86a4a331257618ac964d6ef08d2eeaf16ff679acb4d877806bdb619a6985f305169dd103c7d5e13e7c5c7b9f6f88abd34a1dd6ea3d8d297e3731c5768735f52f0768946d71cd77fce871e4dc291bea196a7d26b713fb9fc4b619b49d7dd18b209118c2bacec76a948368797abcc853d2f85f028ac519ab37f752fce60bbd819ff1cc5683a487e4346005df7e73cbfbb94a9fb544964c497caef19dadbfb937b229cfd38fc95c84c2b983597f4ddbe5a0245c9e7328a172c682a4da9b45fa7ecf5d0e75beaa2bed41ccfd2e78fc3307337311a35d16e53a142ba9cd01bc5aedcb3feb033ec1ba602d76fb453bd91fbaa6fe97f4aefae5c900674b60bcf10217f1e312fa1c12700b4e57b43b7a079aaa3ee133394d4312c77e5f018e7e73c81e676bc56e68a7f7393cb9bc3c13696b89a5f521396e702ebeb888734fe03bd27601dca569d3217c7c0c24fe86c2ec3a0bbef7c24c7459a58a335b2dc2cedb9fb7ccdf8d28
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104410);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_xref(name:"IAVB", value:"0001-B-0503");

  script_name(english:"Target Credential Status by Authentication Protocol - Failure for Provided Credentials");
  script_summary(english:"Reports protocols with credentials provided but no valid credentials found.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was unable to log into the detected authentication protocol,
using the provided credentials, in order to perform credentialed checks.");
  script_set_attribute(attribute:"description", value:
"Nessus failed to successfully authenticate directly to the remote
target on an available authentication protocol. Nessus was able to
connect to the remote port and identify that the service running on
the port supports an authentication protocol, but Nessus failed to
authenticate to the remote service using the provided credentials.

There may have been a failure in protocol negotiation or communication
that prevented authentication from being attempted or all of the
provided credentials for the authentication protocol may have been
invalid. A protocol failure may indicate a compatibility issue with
the protocol configuration. A protocol failure due to an environmental
issue such as resource or congestion issues may also prevent valid
credentials from being identified. See plugin output for error
details.

Please note the following :

- This plugin reports per protocol, so it is possible for
  valid credentials to be provided for one protocol and not
  another. For example, authentication may succeed via SSH
  but fail via SMB, while no credentials were provided for
  an available SNMP service.

- Providing valid credentials for all available
  authentication protocols may improve scan coverage, but
  the value of successful authentication for a given
  protocol may vary from target to target depending upon
  what data (if any) is gathered from the target via that
  protocol. For example, successful authentication via SSH
  is more valuable for Linux targets than for Windows
  targets, and likewise successful authentication via SMB
  is more valuable for Windows targets than for Linux
  targets.");
  script_set_attribute(attribute:"solution", value:
"Address the reported problem(s) so that credentialed checks can be
executed.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("lcx.inc");

var ssh_cred;

# this should only happen if no SSH creds are provided
# as the UI won't allow empty usernames
if (get_kb_item("SSH/root/default_login"))
  ssh_cred = NULL;
else
  ssh_cred = get_kb_item("Secret/SSH/login"); # first cred

# this should only happen if no SNMP community strings are provided
var snmp_default = get_kb_item("SNMP/public/default");

var smb_login_list = get_kb_list("SMB/login_filled/*");
var login_key, smb_domain, smb_login, match_results, i;
var max_index = -1;
foreach login_key (keys(smb_login_list))
{
  match_results = pregmatch(pattern:"^SMB/login_filled/(\d+)$", string: login_key, icase:FALSE);
  if (isnull(match_results)) continue;
  if (!isnull(match_results[1]) && match_results[1] > max_index) max_index = match_results[1];
}
var smb_cred_list = make_array();
for (i = 0; i <= max_index; i++)
{
   login_key = "SMB/login_filled/" + i;
   smb_login = get_kb_item(login_key);
   smb_domain = get_kb_item("SMB/domain_filled/" + i);
   if (!empty_or_null(smb_domain) && !empty_or_null(smb_login)) smb_login = smb_domain + "\" + smb_login;
   if (!empty_or_null(smb_login)) smb_cred_list[login_key] = smb_login;
}

var snmpv3_user = get_kb_item("SNMP/v3/username");
var snmp_comm_names = get_kb_list("SNMP/community_name/*"); # < v3
var iseries_user = get_kb_item("Secret/iSeries/Login");
var esxi_user = get_kb_item("Secret/VMware/login");

var ssh_cred_list = make_list();
var db_cred_list = make_list();
var db_cred = get_kb_item("Database/login");         # first DB cred
if(!empty_or_null(db_cred))
{
  db_cred_list = make_list(db_cred);
  subsequent_db_creds = get_kb_list("Database/*/login");
  if(!empty_or_null(subsequent_db_creds)) db_cred_list = make_list(db_cred_list, subsequent_db_creds);
}

if(!empty_or_null(ssh_cred))
{
  ssh_cred_list = make_list(ssh_cred);
  subsequent_creds = get_kb_list("Secret/SSH/*/login"); # subsequent creds
  if(!empty_or_null(subsequent_creds)) ssh_cred_list = make_list(ssh_cred_list, subsequent_creds);
}


# delete items in list if they contain <like>
# like should be a string
function del_items_like(list, like)
{
  if (empty_or_null(list) || empty_or_null(like)) return list;
  local_var new_list = make_list();
  local_var i;
  local_var idx_del = make_list(); # deleted indices

  for (i = 0; i < len(list); i++)
  {
    if (like >!< list[i])
      new_list = make_list(new_list, list[i]);
    else
      idx_del = make_list(idx_del, i);
  }

  # can't delete all elements
  if (empty(new_list))
  {
    new_list = make_list(new_list, list[idx_del[0]]);
  }

  return new_list;
}

var cred;

function is_supplied_login(type, username)
{
  local_var key;
  if (empty_or_null(type) || empty_or_null(username)) return FALSE;
  if (type == 'SSH' && !isnull(ssh_cred_list))
  {
    foreach cred (ssh_cred_list)
    {
      if (cred == username) return TRUE;
    }
  }
  else if (type == 'SMB' && !isnull(smb_cred_list))
  {
    foreach key (keys(smb_cred_list))
      if (smb_cred_list[key] == username) return TRUE;
  }
  else if (type == 'SNMP' && (!isnull(snmpv3_user) || !isnull(snmp_comm_names)))
  {
    if (snmpv3_user == username) return TRUE;
    else if (!snmp_default && !isnull(snmp_comm_names))
    {
      foreach key (keys(snmp_comm_names))
        if (snmp_comm_names[key] == username) return TRUE;
    }
  }
  else if (type == 'iSeries' && !isnull(iseries_user))
  {
    if (iseries_user == username) return TRUE;
  }
  else if (type == 'SOAP' && !isnull(esxi_user))
  {
    if (esxi_user == username) return TRUE;
  }
  else if (type == 'DB' && !empty_or_null(db_cred_list))
  {
    foreach cred (db_cred_list)
    {
      if (cred == username) return TRUE;
    }
  }

  # else...
  return FALSE;
}

function report_failures_db(prefix, db, port)
{
  local_var failure, match, user, details, detail, line, lines;

  if (islocalhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  var proto = db;

  local_var num_reported = 0;
  local_var kb_prefix = prefix + proto + "/" + port;
  local_var failures = get_kb_list(kb_prefix + "/*/FailureDetails");

  if (isnull(failures)) return 0;
  if (get_kb_list(kb_prefix+"/Success")) return 0;
  local_var report = '';

  report += '  Database        : ' + db;
  proto = "DB";
  report += '\n  Port            : ' + port +
            '\n  Failure details :';

  # list_uniq in case of duplicate keys
  foreach failure (list_uniq(keys(failures)))
  {
    match = pregmatch(pattern:"^"+kb_prefix+"/(.*)/FailureDetails", string: failure, icase:FALSE);
    if (isnull(match)) continue;
    user = match[1];

    if (!is_supplied_login(type:proto, username:user)) continue;

    # failure details
    details = get_kb_list(failure);
    if(empty_or_null(details)) continue;
    details = list_uniq(details); # in case of duplicate values

    foreach detail (details)
    {
      lines = split(detail, sep: '\n', keep: FALSE);
      foreach line (lines)
        report += '\n    ' + user + ' > ' + line;
      num_reported++;
    }
  }

  if (num_reported > 0)
  {
     report = '\nNessus was unable to log into the following host for which\n' +
              'credentials have been provided :\n\n' + report;
     security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  }

  return num_reported;
}

function report_failures(prefix, proto, port)
{
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  if (isnull(proto)) return 0;

  var kb_prefix = prefix + proto + "/" + port;
  if (get_kb_list(kb_prefix+"/Success")) return 0;

  var users = lcx::get_users_with_issues(type:lcx::ISSUES_AUTH,
    port:port, proto:lcx::PROTO_GLOBALS[proto]);

  if (isnull(users) || max_index(users) < 1) return 0;

  var report =
    '\n  Protocol        : ' + proto +
    '\n  Port            : ' + port +
    '\n  Failure details :\n';

  var issues, lines, check, reported, num_reported=0;
  foreach var user (users)
  {
    if (!is_supplied_login(type:proto, username:user))
      continue;

    report += '\n  - User : ' + user;
    issues = lcx::get_issues(type:lcx::ISSUES_AUTH, port:port,
      user:user, proto:lcx::PROTO_GLOBALS[proto]);

    reported = "|";
    foreach var issue (issues)
    {
      check = issue['plugin'] + ":" + issue['text'] + "|";
      if ("|" + check >< reported) continue;
      reported += check;

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
      '\nNessus was unable to log into the following host for which' +
      '\ncredentials have been provided :\n' + report;
    security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  }

  return num_reported;
}

failures = get_kb_list("Host/Auth/*/Failure");

host_ports = make_list();
db_ports = make_list();

pat = "^Host/Auth/([A-Za-z]+/[0-9]+)/.*";
foreach fail (keys(failures))
{
  match = pregmatch(pattern:pat, string:fail, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];
  host_ports = make_list(host_ports, protoport);
}

db_failures = get_kb_list("DB_Auth/*/FailureDetails");
pat = "DB_Auth/([A-Za-z0-9]+/\d+)/.*";
foreach fail (keys(db_failures))
{
  match = pregmatch(pattern:pat, string:fail, icase:FALSE);
  if (isnull(match)) continue;

  db_port = match[1];
  db_ports = make_list(db_ports, db_port);
}

var num_reported = 0;
var tmp;

if (!empty(host_ports))
{
  foreach p (list_uniq(host_ports))
  {
    tmp = split(p, sep:'/', keep:FALSE);
    num_reported += report_failures(prefix:"Host/Auth/", proto:tmp[0], port:tmp[1]);
  }
}

var db;

{
  foreach p (list_uniq(db_ports))
  {
    tmp = split(p, sep:'/', keep:FALSE);
    num_reported += report_failures_db(prefix:"DB_Auth/", db:tmp[0], port:tmp[1]);
  }
}

# failures reported in kb, but success as well. no need to report failures
if (num_reported == 0) exit(0, "No authentication failures with user supplied credentials to report.");
