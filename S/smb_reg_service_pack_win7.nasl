#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52459);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_name(english:"Microsoft Windows SMB Registry : Win 7 / Server 2008 R2 Service Pack Detection");
  script_summary(english:"Determines the remote SP");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to determine the service pack installed on
the remote system.");
  script_set_attribute(attribute:"description", value:
"It is possible to determine the Service Pack version of the Windows
7 / Server 2008 R2 system by reading the registry key
'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CSDVersion'.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 139;

win = get_kb_item_or_exit("SMB/WindowsVersion");
sp = get_kb_item("SMB/CSDVersion");

if (win == "6.1")
{
  if (!isnull(sp) && ereg(pattern:"Service Pack [1-9]", string:sp))
  {
    set_kb_item(name:"SMB/7/ServicePack", value:sp);
    if (report_verbosity > 0)
    {
      report = '\n' + 'The remote Windows 7 / Server 2008 R2 system has ' + sp + ' applied.\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
    exit(0);
  }
  else exit(0, "There is no service pack installed.");
}
else audit(AUDIT_OS_NOT, "Windows 7 / Server 2008 R2");
