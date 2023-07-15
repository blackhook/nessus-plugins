#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92417);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_name(english:"Direct3D Recent Program");
  script_summary(english:"Most recent program to use Direct3D."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate the most recent program to use Direct3D
for each user on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to query the registry to find the most recent program
to use Direct3D for each user on the remote Windows host.");
  # https://docs.microsoft.com/en-us/previous-versions/windows/desktop/bb153256(v=vs.85)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e275bc08");
  # https://docs.microsoft.com/en-us/windows/desktop/direct3d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7def0916");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl", "set_kb_system_name.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("data_protection.inc");

# Disable if GDPR is set
data_protection::disable_plugin_if_set();

# HKEY_USERS\\<sid>\\Software\\Microsoft\\Direct3D\\MostRecentApplication
key = '\\Software\\Microsoft\\Direct3D\\MostRecentApplication';
value = get_hku_key_values(key:key);

report = '';
foreach user (keys(value))
{
  report += user + '\n';
  foreach d3d (value[user])
  {
    report += '  - ' + get_ascii_printable(string:d3d) + '\n';
  }
  report += '\n';
}

if (strlen(report) > 0)
{
  security_report_v4(extra:report, port:0, severity:SECURITY_NOTE);
}
else
{
  exit(0, "No Direct3D history to report.");
}
