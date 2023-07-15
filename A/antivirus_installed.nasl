#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if (description)
{
 script_id(16193);
 script_version("1.49");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

 script_name(english:"Antivirus Software Check"); # Do not change this
 script_summary(english:"Checks that the remote host has an antivirus.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"An antivirus application is installed on the remote host, and its
engine and virus definitions are up to date.");
 # https://www.tenable.com/blog/auditing-anti-virus-software-without-an-agent
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ed73b52");
 script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/blog/auditing-anti-virus-products-with-nessus");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_add_preference(name:"Delay (in days, between 0 and 7) :", type:"entry", value:0);

 script_dependencies(
  "netbios_name_get.nasl",
  "smb_login.nasl",
  "smb_registry_full_access.nasl",
  "smb_enum_services.nasl",
  "kaspersky_installed.nasl",
  "mcafee_installed.nasl",
  "panda_antivirus_installed.nasl",
  "trendmicro_installed.nasl",
  "savce_installed.nasl",
  "bitdefender_installed.nasl",
  "nod32_installed.nasl",
  "sophos_installed.nasl",
  "fcs_installed.nasl",
  "fep_installed.nasl",
  "checkpoint_zonealarm_installed.nasl",
  "trendmicro_serverprotect_installed.nasl",
  "mcafee_vsel_installed.nasl",
  "wmi_fsecure_av_check.nbin",
  "macosx_sophos_installed.nasl",
  "macosx_xprotect_installed.nasl",
  "avg_internet_security_installed.nbin",
  "avast_installed.nasl",
  "spysweeper_corp_installed.nasl",
  "vmware_carbon_black_cloud_endpoint_standard_win_status.nbin",
  "vmware_carbon_black_cloud_endpoint_standard_mac_status.nbin",
  "bitdefender_endpoint_security_tools_status.nasl"
 );
 script_require_ports("Services/ssh", 22, 139, 445);

 exit(0);
}

include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

software = make_list(
  "AVG Internet Security",
  "Avast",
  "Kaspersky",
  "McAfee",
  "McAfee_VSEL",
  "Norton",
  "Panda",
  "TrendMicro",
  "TrendMicro ServerProtect",
  "SAVCE",
  "BitDefender",
  "NOD32",
  "OneCare",
  "Sophos",
  "Forefront_Client_Security",
  "Forefront_Endpoint_Protection",
  "F-Secure",
  "SophosOSX",
  "SpySweeperEnt",
  "XProtect",
  "Check Point ZoneAlarm",
  'VMware Carbon Black Cloud Endpoint Standard',
  'Confer',
  'Bitdefender Endpoint Security Tools'
);

problem_installs = make_list();
port = '';
report = '';

foreach av (software)
{
  if (get_kb_item("Antivirus/" + av + "/installed"))
  {
    info = get_kb_item("Antivirus/" + av + "/description");
    if (info)
    {
        if (!port)
        {
          if ("OSX" >< av || "Confer" >< av || "XProtect" >< av) port = 0;
          else if ("McAfee_VSEL" >< av) port = 0;
          else
          {
            port = get_kb_item("SMB/transport");
            if (!port) port = 445;
          }
        }
        report += '\n' + av + ' :' +
                  '\n' + info;
    }
    else problem_installs = make_list(problem_installs, av);
  }
}


if (report)
{
  security_report_v4(severity:SECURITY_NOTE,port:port, extra:report);
  exit(0);
}
else
{
  if (max_index(problem_installs) == 0) exit(0, "The host does not have an antivirus that Nessus checks for.");
  else exit(1, "There is no description available for " + join(problem_installs, sep:" & ") + ". Please contact Tenable support.");
}
