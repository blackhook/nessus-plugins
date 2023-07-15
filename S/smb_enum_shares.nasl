#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10395);
 script_version("1.48");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

 script_name(english:"Microsoft Windows SMB Shares Enumeration");
 script_summary(english:"Gets the list of remote shares");

 script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate remote network shares.");
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host, Nessus was able to enumerate the
network share names.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl","smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("data_protection.inc");

if (thorough_tests) max_shares = 10000;
else max_shares = 200;

login = kb_smb_login();
pass = kb_smb_password();
dom = kb_smb_domain();
port = kb_smb_transport();

report_access_trouble = TRUE;
report_auth_failure   = TRUE;
if ( ! login )
{
  report_auth_failure   = FALSE;
  report_access_trouble = FALSE;
  login = pass = dom = NULL;
  if ( !supplied_logins_only && get_kb_item("SMB/any_login") )
  {
    login = "Nessus" + rand();
    pass  = "Nessus" + rand();
  }
}

if(! smb_session_init(report_access_trouble:report_access_trouble, report_auth_failure:report_auth_failure))
  audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

shares = NetShareEnum (level:SHARE_INFO_0);
if ( isnull(shares) ) shares = NetShareEnum (level:SHARE_INFO_1);
NetUseDel ();

# NetShareEnum (when called with level SHARE_INFO_0 or SHARE_INFO_1) returns either NULL or a list of share names
# Using exit code 0 since error condition can't be assumed from a NULL return value
if (isnull(shares)) exit(0, 'NetShareEnum did not return share information.');

res = NULL;
nshares = 0;
foreach share (shares)
{
  nshares++;
  if (nshares <= max_shares)
  {
    set_kb_item(name:"SMB/shares", value:share);
    res = res + '  - ' + share + '\n';
  }
}

# Using exit code 1 here since it's expected that a non-NULL response is a list of share names
if (nshares == 0) exit(1, 'No shares found in NetShareEnum response.');

if ( login ) login = "when logged in as " + data_protection::sanitize_user_enum(users:login);
if (nshares <= max_shares)
{
  report =
    '\nHere are the SMB shares available on the remote host ' + login + ':\n\n' +
    data_protection::sanitize_user_enum(users:res);
}
else
{
  report =
    '\n' + nshares + ' SMB shares are available on the remote host ' + login + '.' +
    '\nHere are the first ' + max_shares + ' :\n\n' +
    data_protection::sanitize_user_enum(users:res);
}

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
