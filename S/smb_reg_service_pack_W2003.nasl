#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17662);
 script_version("1.35");
 script_name(english:"Microsoft Windows SMB Registry : Windows 2003 Server Service Pack Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"It was possible to determine the service pack installed on 
the remote system." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the Service Pack version of the Windows
2003 system.  by reading the registry key
'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CSDVersion'." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/31");

 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"agent", value:"windows");
script_end_attributes();

 script_summary(english:"Determines the remote SP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.2" )
{
 if ( ereg(pattern:"Service Pack [1-9]", string:sp) )
 {
  set_kb_item(name:"SMB/Win2003/ServicePack", value:sp);
  report = string ("\n",
		"The remote Windows 2003 system has ",sp," applied",
                "\n");
  security_note(extra:report, port:port);
  exit(0);
 }
}

