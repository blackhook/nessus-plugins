##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(102683);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-8543");
  script_bugtraq_id(98824);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"Microsoft Windows Search Remote Code Execution Vulnerability (CVE-2017-8543)");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to overflow an allocated buffer by sending crafted
windows search protocol packets.");
  script_set_attribute(attribute:"description", value:
"By sending two malformed Windows Search Protocol packets over SMB,
Nessus was able to overflow an allocated buffer.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8543
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33c94e8d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, 2008 R2, 2012,
8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_enum_shares.nasl", "smb_login_as_users.nasl");
  script_require_keys("SMB/transport", "SMB/name");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("mswsp.inc");
include("agent.inc");

if(agent()) exit(0,"This plugin is disabled on Nessus Agents.");

service_name = "Windows Search Protocol";
port = kb_smb_transport();
lg = kb_smb_login();
pw =  kb_smb_password();
report_auth_failure = TRUE;
if (empty_or_null(lg))
{
  lg = "";
  report_auth_failure = FALSE;
}
if (empty_or_null(pw)) pw = "";
dom = kb_smb_domain();

ln = NULL;
ntlm = NULL;

host_ip = get_host_ip();

# Ensure the port is open.
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Use latest version of SMB that Nessus and host share (likely SMB 2.002)
if (!smb_session_init(smb2:TRUE, report_access_trouble:FALSE, report_auth_failure:report_auth_failure))
  audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:lg, password:pw, domain:dom, share:"IPC$");
if ( r != 1 )
{
  audit(AUDIT_FN_FAIL, "NetUseAdd");
}

null_fid = crap(data:'\xff', length:16);
MSWSPname = "MsFteWds";
smb2_ioctl(
                fid:null_fid,
                code:FSCTL_PIPE_WAIT,
                data:MSWSPname
                );

ret = smb2_create(
                name:MSWSPname,
                desired_access: 0x12019f,
                flags_attributes: 0, 
                share_mode: 7, # Read, Write, Delete
                create_disposition:1, 
                create_options:0x40
                );
if (isnull(ret) || max_index(ret) < 1)
{
  NetUseDel();
  audit(AUDIT_SVC_ERR, port);
}
mswsp_fid = ret[0];

# WSP Connect
data = WSP_CPMConnect();
status = wsp_smb_send_recv(fid:mswsp_fid,data:data);
if (isnull(status) || status != S_OK)
{
  NetUseDel();
  audit(AUDIT_SVC_ERR, port);
}

shares = get_kb_list("SMB/shares");
if(isnull(shares)) shares = make_list("WINNT$", "C$", "D$", "ADMIN$", "ROOT", "c", "d");

foreach share (shares)
{
  # WSP CreateQuery
  data = WSP_CPMCreateQuery(host:host_ip,share:share);
  status = wsp_smb_send_recv(fid:mswsp_fid,data:data);
  if (isnull(status) || status != S_OK) continue;

  # WSP SetBindings
  data = WSP_CPMSetBindings(c:1,s:0x708);
  status = wsp_smb_send_recv(fid:mswsp_fid,data:data);
  if (isnull(status) || status != S_OK) continue;

  # WSP GetRows
  data = WSP_CPMGetRows(c:1,s:0x700);
  status = wsp_smb_send_recv(fid:mswsp_fid,data:data);
  if (isnull(status)) continue;

  # WSP FreeCursor
  data = WSP_FreeCursor(c:1);
  wsp_smb_send_recv(fid:mswsp_fid,data:data);

  if (status == S_OK || status == S_ENDOFROWSET)
  {
    NetUseDel();
    report = "Nessus was able to trigger a buffer overflow over SMB through the" + '\n' +
             "Windows Search Protocol (WSP) on the following share : " + '\n\n' +
             "  " + share;

    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
    exit(0);
  }
}

# Not vulnerable or no indexed shares available
NetUseDel();
audit(AUDIT_LISTEN_NOT_VULN, service_name, port);
