#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(100871);
 script_version("1.2");
 script_cvs_date("Date: 2019/11/22");

 script_name(english:"Microsoft Windows SMB Versions Supported (remote check)");
 script_summary(english:"Checks which versions of SMB are enabled on the remote host.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain information about the version of SMB running
on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to obtain the version of SMB running on the remote
host by sending an authentication request to port 139 or 445.

Note that this plugin is a remote check and does not work on agents.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139,445);
 exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("smb_func.inc");

smbv1 = get_kb_item("SMB/SMBv1_is_supported");

port = kb_smb_transport();

if (smb_session_init(smb2:TRUE))
{
  r = NetUseAdd(share:"IPC$");
  if (r == 1)
  {
    NetUseDel();
  }

  if (!empty_or_null(Session[24]) && Session[24]==1)
  {
    set_kb_item(name:"SMB/SMBv2_is_supported", value:TRUE);
    smbv2 = TRUE;
  }
  else
    set_kb_item(name:"SMB/SMBv2_is_supported", value:FALSE);
}

if ( smbv1 || smbv2 )
{
  report = '\nThe remote host supports the following versions of SMB :\n';
  if(!empty_or_null(smbv1) && smbv1 == 1) report += '  SMBv1\n';
  if(!empty_or_null(smbv2)) report += '  SMBv2\n';

  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else audit(AUDIT_NOT_DETECT, 'SMB');
