#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(26920);
  script_version("1.42");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/07");

  script_cve_id("CVE-1999-0519", "CVE-1999-0520", "CVE-2002-1117");
  script_bugtraq_id(494);

  script_name(english:"SMB NULL Session Authentication");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote host with a NULL session.");
  script_set_attribute(attribute:"description", value:
"The remote host is running and SMB protocol. It is possible to log into the browser or spoolss pipes using a NULL
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
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0519");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_login.nasl");
  script_require_keys("SMB/null_session_suspected");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');

# make sure we accually think this is possible
get_kb_item_or_exit('SMB/null_session_suspected');

var port = kb_smb_transport();
# we need the  netbios name of the host
var name = kb_smb_name();
if(!name) exit(0, 'Unable to obtain the Netbios name of the host.');

# open a socket for connection
var soc = open_sock_tcp(port);
if(!soc) exit(AUDIT_SOCK_FAIL, port);

# start a session to IPC$
session_init(socket:soc,hostname:name);
var ret = NetUseAdd (login:'', password:'', domain:'', share:'IPC$');

# If conneciton fails close socket and exit
if (ret != 1)
{
  close(soc);
  exit(0, 'Could not connect to IPC$ using NULL credentials');
}

# make the list of pipes to cycle through
var pipe_uuids = make_array();
pipe_uuids['browser']  = '6bffd098-a112-3610-9833-012892020162';
pipe_uuids['spoolss']  = '12345678-1234-ABCD-EF00-0123456789AB';
pipe_uuids['netlogon'] = '12345678-1234-ABCD-EF00-01234567CFFB';
pipe_uuids['lsarpc']   = 'c681d488-d850-11d0-8c52-00c04fd90f7e';
pipe_uuids['samr']     = '12345778-1234-ABCD-EF00-0123456789AC';

# set up foreach vars
var vuln = FALSE;
var report = '';
var fid = NULL;

foreach var pipe (keys(pipe_uuids))
{
  # attempt to connect to the pipe
  fid = bind_pipe (pipe:'\\'+pipe, uuid:pipe_uuids[pipe], vers:0);
  if (!isnull(fid))
  {
    # lets set a kb item to track the pipes
    set_kb_item(name:'SMB/null_session_enabled/'+pipe, value:TRUE);
    if (pipe == 'browser' || pipe == 'spoolss')
    {
      report += '  - ' + pipe + '\n';
      vuln = TRUE;
    }
  }
}

# lets clean up our connections
NetUseDel();
close(soc);

# time to report
if (vuln)
{
  set_kb_item(name:'SMB/null_session_enabled', value:TRUE);
  report = 'It was possible to bind to the following pipes:\n' + report;
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else
  exit(0, 'It was possible to connect to IPC$, but it was not possible to bind to any pipe.');
