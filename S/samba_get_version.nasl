#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(104887);
 script_version("1.2");
 script_cvs_date("Date: 2019/11/22");

 script_name(english:"Samba Version");
 script_summary(english:"Extracts the samba version.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the samba version from the remote 
operating system.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to obtain the samba version from the remote 
operating by sending an authentication request to port 139 or 445. 
Note that this plugin requires SMB1 to be enabled on the host.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Misc.");

 script_dependencies("smb_nativelanman.nasl");
 exit(0);
}

include("misc_func.inc");
include("audit.inc");
include("global_settings.inc");

port = get_kb_item("SMB/transport");
if (!port) port=445;

ver = get_kb_item("SMB/Samba/version");
if (empty_or_null(ver)) audit(AUDIT_NOT_INST, "Samba");
report += '\nThe remote Samba Version is : ' + ver;
security_note(port:port, extra:report);

