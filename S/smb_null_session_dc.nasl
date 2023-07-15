#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(162529);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/24");

  script_name(english:"SMB NULL Session Authentication (Domain Controller)");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote Windows host with a NULL session.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an SMB protocol. It is possible to log into the netlogon, lsarpc, or samr pipes using a NULL
session (i.e., with no login or password).

Depending on the configuration, it may be possible for an unauthenticated, remote attacker to leverage this issue to get
information about the remote host.");
  # https://docs.microsoft.com/en-gb/windows/win32/rpc/null-sessions?redirectedfrom=MSDN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e32d594f");
  # https://social.technet.microsoft.com/Forums/windowsserver/en-US/52899d34-0033-41f5-b5e0-2325dd827244/disabling-null-sessions-on-windows-server-20032008?forum=winserverGP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9182e66b");
  # http://technet.microsoft.com/en-us/library/cc785969(WS.10).aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a33fe205");
  script_set_attribute(attribute:"solution", value:
"Please contact the product vendor for recommended solutions.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_null_session.nasl");
  script_require_keys("SMB/null_session_enabled");
  script_require_ports(139, 445);

  exit(0);
}

var pipes = make_list('netlogon', 'lsarpc', 'samr');

var vuln = FALSE;
var report = '';

foreach var pipe (pipes)
{
  if (get_kb_item('SMB/null_session_enabled/'+pipe))
  {
    report += '  - ' + pipe + '\n';
    vuln = TRUE;
  }
}

if (vuln)
{
  var port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;
  report = 'It was possible to bind to the following pipes:\n' + report;
  security_report_v4(port:get_kb_item("SMB/transport"), severity:SECURITY_NOTE, extra:report);
}
else
  exit(0, 'It was not possible to bind to any pipe.');
