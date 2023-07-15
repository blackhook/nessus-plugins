#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include("compat.inc");

if (description)
{
  script_id(124120);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/17 14:36:05");

  script_name(english:"Microsoft Outlook Attachment Previewing Enabled");
  script_summary(english:"Checks the trust center settings of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"Microsoft Outlook application that is installed on the remote host has attachment
previewing enabled.");
  script_set_attribute(attribute:"description", value:
"Microsoft Outlook application that is installed on the remote host has attachment
previewing enabled.");

  script_set_attribute(attribute:"solution", value:
"Disable attachment previewing settings.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

registry_init();

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

office_vers = make_list(
  '14.0',
  '15.0',
  '16.0'
);

#For Reporting
office_disp  = {
  '14.0': 'Microsoft Office 2010',
  '15.0': 'Microsoft Office 2013',
  '16.0': 'Microsoft Office 2016'
};

report = '';

foreach ver (office_vers)
{
    #it's a way to check if this office is actually installed
    if (get_kb_item('SMB/Office/' + ver + '/Bitness'))
    {
        #if office installed and this value doesn't exist or equal 0, it's vulnerable
        value = get_registry_value(handle:hklm,
            item:'Software\\Microsoft\\Office\\'+ ver +  
            '\\Outlook\\Preferences\\DisableAttachmentPreviewing');

        if (value != 1)
        {
            report += 'Outlook application in ' + office_disp[ver] + 
            ' has attachment previewing enabled.\n';
        }
    }
}
RegCloseKey(handle:hklm);
close_registry();

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);