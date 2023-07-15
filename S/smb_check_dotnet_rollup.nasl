#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99364);
  script_version("1.43");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/03");

  script_name(english:"Microsoft .NET Security Rollup Enumeration");
  script_summary(english:"Enumerates installed Microsoft .NET security rollups.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates installed Microsoft .NET security rollups.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the Microsoft .NET security rollups
installed on the remote Windows host.");
  # https://blogs.msdn.microsoft.com/dotnet/2016/10/11/net-framework-monthly-rollups-explained/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?662e30c9");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl","wmi_enum_qfes.nbin", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "installed_sw/Microsoft .NET Framework");
  script_require_ports(139, 445);
  script_timeout(30*60);

  exit(0);
}

include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");


if (!defined_func("nasl_level") || nasl_level() < 6000 ) exit(0);

# in order from latest to earliest
var rollup_dates = make_list(
  "04_2017",
  "05_2017",
  "09_2017",
  "01_2018",
  "05_2018",
  "07_2018",
  "08_2018",
  "09_2018",
  "12_2018",
  "01_2019",
  "02_2019",
  "05_2019",
  "07_2019",
  "09_2019",
  "01_2020",
  "05_2020",
  "07_2020",
  "08_2020",
  "09_2020",
  "10_2020",
  "02_2021",
  "01_2022",
  "04_2022",
  "05_2022",
  "09_2022",
  "11_2022",
  "12_2022",
  "02_2023",
  "06_2023"
);

# .NET rollups
var rollup_patches = {
  # April 2017
  "04_2017" : [
        # Vista SP2 / 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4014561, "sec": 4014571}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36387"}, {"cum": 4014559, "sec": 4014566}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014553, "sec": 4014558}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4014565, "sec": 4014573}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36387"}, {"cum": 4014559, "sec": 4014566}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014553, "sec": 4014558}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014553, "sec": 4014558}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4014547, "sec": 4014552}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.management.dll", "version": "2.0.50727.8758"}, {"cum": 4014563, "sec":4014572}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36386"}, {"cum": 4014557, "sec": 4014564}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014548, "sec": 4014560}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014548, "sec": 4014560}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4014545, "sec": 4014549}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.management.dll", "version": "2.0.50727.8758"}, {"cum": 4014567, "sec": 4014574}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36386"}, {"cum": 4014555, "sec": 4014562}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014551, "sec": 4014556}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014551, "sec": 4014556}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4014546, "sec": 4014550}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4015221}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4015221}],
        # Windows 10 1511
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4015219}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4015219}],
        # Windows 10 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4015217}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4015217}],
        # Windows 10 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8792"}, {"cum": 4015583}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.7.2092.0"}, {"cum": 4015583}]
 ],
  # May 2017
  "05_2017" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019115, "sec": 4019109}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36391"}, {"cum": 4019115, "sec": 4019109}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019115, "sec": 4019109}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36391"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019112, "sec": 4019108}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36389"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019113, "sec": 4019110}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36389"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019114, "sec": 4019111}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019474}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019474}],
        # Windows 10 1511
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019473}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019473}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019472}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019472}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8793"}, {"cum": 4016871}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.2093.0"}, {"cum": 4016871}]
 ],
  # Sep 2017
  "09_2017" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8771"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.0.30319.36415"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.6.1", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.6.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.7", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041086, "sec": 4041093}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8771"}, {"cum": 4041083, "sec": 4041090}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.0.30319.36415"}, {"cum": 4041083, "sec": 4041090}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041083, "sec": 4041090}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041083, "sec": 4041090}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041083, "sec": 4041090}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041083, "sec": 4041090}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8771"}, {"cum": 4041084, "sec": 4041091}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.0.30319.36415"}, {"cum": 4041084, "sec": 4041091}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041084, "sec": 4041091}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041084, "sec": 4041091}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041084, "sec": 4041091}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041084, "sec": 4041091}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8771"}, {"cum": 4041085, "sec": 4041092}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.0.30319.36415"}, {"cum": 4041085, "sec": 4041092}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041085, "sec": 4041092}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041085, "sec": 4041092}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041085, "sec": 4041092}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4041085, "sec": 4041092}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8771"}, {"cum": 4038781}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.6.1655.0"}, {"cum": 4038781}],
        # Windows 10 1511
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8771"}, {"cum": 4038783}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.6.1655.0"}, {"cum": 4038783}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8771"}, {"cum": 4038782}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4038782}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4038782}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.remoting.dll", "version": "2.0.50727.8801"}, {"cum": 4038788}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.remoting.dll", "version": "4.7.2114.0"}, {"cum": 4038788}]
  ],
  # January 2018
  "01_2018" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.xml.dll", "version": "2.0.50727.8773"}, {"cum": 4054996, "sec": 4054174}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v3.0", "file": "smdiagnostics.dll", "version": "3.0.4506.8789"}, {"cum":4054996, "sec":4054174}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.0.30319.36430"}, {"cum": 4054995, "sec": 4054172}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.6.1", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.6.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.7", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4041086, "sec": 4041093}],
        [{".net_version":"4.7.1", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4041086, "sec": 4041093}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "smdiagnostics.dll", "version": "3.0.4506.8789"}, {"cum": 4054998, "sec": 4054176}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.0.30319.36430"}, {"cum": 4054172, "sec": 4054995}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055002, "sec": 4054183}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055002, "sec": 4054183}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055002, "sec": 4054183}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055002, "sec": 4054183}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "SMDiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055002, "sec": 4054183}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "smdiagnostics.dll", "version": "3.0.4506.8789"}, {"cum": 4055000, "sec": 4041091}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.0.30319.36427"}, {"cum": 4054994, "sec": 4054171}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055000, "sec": 4054181}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055000, "sec": 4054181}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055000, "sec": 4054181}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055000, "sec": 4054181}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055000, "sec": 4054181}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "smdiagnostics.resources.dll", "version": "3.0.4506.7903"}, {"cum": 4054999, "sec": 4054177}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.0.30319.36427"}, {"cum": 4054993, "sec": 4054170}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055001, "sec": 4054182}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055001, "sec": 4054182}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055001, "sec": 4054182}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055001, "sec": 4054182}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "smdiagnostics.dll", "version": "4.7.2612.0"}, {"cum": 4055001, "sec": 4054182}],
  ],
  # May 2018
  "05_2018" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8784"}, {"cum": 4095873, "sec": 4095513}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v3.0", "file": "system.security.dll", "version": "2.0.50727.8784"}, {"cum": 4095873, "sec": 4095513}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.0.30319.36440"}, {"cum": 4096495, "sec": 4095519}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.7.2650.0"}, {"cum": 4096418, "sec": 4096237}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8784"}, {"cum": 4095874, "sec": 4095514}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.0.30319.36440"}, {"cum": 4096495, "sec": 4095519}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.7.2650.0"}, {"cum": 4096418, "sec": 4096237}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.7.2650.0"}, {"cum": 4096418, "sec": 4096237}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.7.2650.0"}, {"cum": 4096418, "sec": 4096237}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.7.2650.0"}, {"cum": 4096418, "sec": 4096237}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Security.dll", "version": "4.7.2650.0"}, {"cum": 4096418, "sec": 4096237}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8784"}, {"cum": 4095872, "sec": 4095512}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.0.30319.36440"}, {"cum": 4096494, "sec": 4095518}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096416, "sec": 4096235}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096416, "sec": 4096235}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096416, "sec": 4096235}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096416, "sec": 4096235}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096416, "sec": 4096235}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8784"}, {"cum": 4095875, "sec": 4095515}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.0.30319.36440"}, {"cum": 4095876, "sec": 4095517}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096417, "sec": 4096236}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096417, "sec": 4096236}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096417, "sec": 4096236}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096417, "sec": 4096236}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.2650.0"}, {"cum": 4096417, "sec": 4096236}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.security.dll", "version": "2.0.50727.8771"}, {"cum": 4103716}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.6.1661.0"}, {"cum": 4103716}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.6.1661.0"}, {"cum": 4103716}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.6.1661.0"}, {"cum": 4103716}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.security.dll", "version": "2.0.50727.8784"}, {"cum": 4103723}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.7.2650.0"}, {"cum": 4103723}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.7.2650.0"}, {"cum": 4103723}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.7.2650.0"}, {"cum": 4103723}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.security.dll", "version": "2.0.50727.8804"}, {"cum": 4103731}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.7.2650.0"}, {"cum": 4103731}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.7.2650.0"}, {"cum": 4103731}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.security.dll", "version": "2.0.50727.8804"}, {"cum": 4103727}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.7.2650.0"}, {"cum": 4103727}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.security.dll", "version": "2.0.50727.8930"}, {"cum": 4103721}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.security.dll", "version": "4.7.3101.0"}, {"cum": 4103721}]

  ],
  # July 2018
  "07_2018" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8789"}, {"cum": 4338422, "sec": 4338611}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8789"}, {"cum": 4338422, "sec": 4338611}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36450"}, {"cum": 4338417, "sec": 4338602}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338420, "sec": 4338606}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8789"}, {"cum": 4338423, "sec": 4338612}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36450"}, {"cum": 4338417, "sec": 4338602}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338420, "sec": 4338606}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338420, "sec": 4338606}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338420, "sec": 4338606}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338420, "sec": 4338606}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338420, "sec": 4338606}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338420, "sec": 4338606}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8789"}, {"cum": 4338421, "sec": 4338610}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36450"}, {"cum": 4338416, "sec": 4338601}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338418, "sec": 4338604}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338418, "sec": 4338604}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338418, "sec": 4338604}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338418, "sec": 4338604}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338418, "sec": 4338604}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338418, "sec": 4338604}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8789"}, {"cum": 4338424, "sec": 4338613}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36450"}, {"cum": 4338415, "sec": 4338600}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338419, "sec": 4338605}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338419, "sec": 4338605}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338419, "sec": 4338605}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338419, "sec": 4338605}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338419, "sec": 4338605}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338419, "sec": 4338605}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8789"}, {"cum": 4338829}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.6.1665.0"}, {"cum": 4338829}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.6.1665.0"}, {"cum": 4338829}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.6.1665.0"}, {"cum": 4338829}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8789"}, {"cum": 4338814}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338814}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338814}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338814}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338814}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8805"}, {"cum": 4338826}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338826}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338826}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338826}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8831"}, {"cum": 4338825}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338825}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3130.0"}, {"cum": 4338825}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8933"}, {"cum": 4338819}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3131.0"}, {"cum": 4338819}]

  ],
  # August 2018
  "08_2018" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8793"}, {"cum": 4344151, "sec": 4344176}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8793"}, {"cum": 4344151, "sec": 4344176}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36460"}, {"cum": 4344149, "sec": 4344173}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8793"}, {"cum": 4344152, "sec": 4344177}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36460"}, {"cum": 4344149, "sec": 4344173}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344146, "sec": 4344167}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344146, "sec": 4344167}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344146, "sec": 4344167}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344146, "sec": 4344167}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344146, "sec": 4344167}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344146, "sec": 4344167}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8793"}, {"cum": 4344150, "sec": 4344175}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36460"}, {"cum": 4344148, "sec": 4344172}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344144, "sec": 4344165}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344144, "sec": 4344165}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344144, "sec": 4344165}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344144, "sec": 4344165}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344144, "sec": 4344165}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344144, "sec": 4344165}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8793"}, {"cum": 4344153, "sec": 4344178}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.0.30319.36460"}, {"cum": 4344147, "sec": 4344171}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344145, "sec": 4344166}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344145, "sec": 4344166}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344145, "sec": 4344166}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344145, "sec": 4344166}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344145, "sec": 4344166}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3133.0"}, {"cum": 4344145, "sec": 4344166}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8793"}, {"cum": 4343892}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.6.1683.0"}, {"cum": 4343892}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.6.1683.0"}, {"cum": 4343892}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.6.1683.0"}, {"cum": 4343892}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8793"}, {"cum": 4343887}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343887}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343887}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343887}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343887}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8807"}, {"cum": 4343885}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343885}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343885}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343885}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8833"}, {"cum": 4343897}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343897}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343897}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "sos.dll", "version": "2.0.50727.8935"}, {"cum": 4343909}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "sos.dll", "version": "4.7.3132.0"}, {"cum": 4343909}]
  ],
  # September 2018
  "09_2018" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8811", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457043, "sec": 4457054}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8811", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457043, "sec": 4457054}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.0.30319.36465"}, {"cum": 4457038, "sec": 4457030}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457035, "sec": 4457027}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8811", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457044, "sec": 4457055}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.0.30319.36465"}, {"cum": 4457038, "sec": 4457030}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457035, "sec": 4457027}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457035, "sec": 4457027}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457035, "sec": 4457027}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457035, "sec": 4457027}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457035, "sec": 4457027}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.Workflow.Runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457035, "sec": 4457027}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8811", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457042, "sec": 4457053}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36465"}, {"cum": 4457037, "sec": 4457029}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457033, "sec": 4457025}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457033, "sec": 4457025}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457033, "sec": 4457025}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457033, "sec": 4457025}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457033, "sec": 4457025}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457033, "sec": 4457025}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8811", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457045, "sec": 4457056}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36465"}, {"cum": 4457036, "sec": 4457028}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457034, "sec": 4457026}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457034, "sec": 4457026}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457034, "sec": 4457026}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457034, "sec": 4457026}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457034, "sec": 4457026}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457034, "sec": 4457026}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.workflow.runtime.dll", "version": "3.0.4203.8811", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457132}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.6.1690.0"}, {"cum": 4457132}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.6.1690.0"}, {"cum": 4457132}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.6.1690.0"}, {"cum": 4457132}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.workflow.runtime.dll", "version": "3.0.4203.8811", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457131}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457131}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457131}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457131}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457131}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.workflow.runtime.dll", "version": "3.0.4203.8803", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457138}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457138}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457138}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457138}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.workflow.runtime.dll", "version": "3.0.4203.8837", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457142}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457142}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457142}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.workflow.runtime.dll", "version": "3.0.4203.8934", "winsxs": {"dir_pat" : "msil_system.workflow.runtime", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4457128}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "System.workflow.runtime.dll", "version": "4.7.3180.0"}, {"cum": 4457128}]
  ],
  # December 2018
  "12_2018" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8815", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4471102, "sec":  4470633}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8815", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4471102, "sec": 4470633}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.0.30319.36480"}, {"cum": 4470637, "sec": 4470493}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470640, "sec": 4470500}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8814", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4470641, "sec": 4470600}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.0.30319.36480"}, {"cum": 4470637, "sec": 4470493}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470640, "sec": 4470500}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470640, "sec": 4470500}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470640, "sec": 4470500}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470640, "sec": 4470500}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470640, "sec": 4470500}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470640, "sec": 4470500}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8814", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4470629, "sec": 4470601}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.0.30319.36480"}, {"cum": 4470623, "sec": 4470492}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470638, "sec": 4470498}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470638, "sec": 4470498}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470638, "sec": 4470498}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470638, "sec": 4470498}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470638, "sec": 4470498}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470638, "sec": 4470498}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8814", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4470630, "sec": 4470602}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.0.30319.36480"}, {"cum": 4470622, "sec": 4470491}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470639, "sec": 4470499}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470639, "sec": 4470499}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470639, "sec": 4470499}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470639, "sec": 4470499}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470639, "sec": 4470499}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470639, "sec": 4470499}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8814", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4471323}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.6.1715.0"}, {"cum": 4471323}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.6.1715.0"}, {"cum": 4471323}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.6.1715.0"}, {"cum": 4471323}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8814", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4471321}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471321}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471321}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471321}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471321}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8804", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4471327}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471327}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471327}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471327}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8838", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4471329}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471329}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471329}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.8935", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4471324}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4471324}],
        # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
         [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.extensions.dll", "version": "3.5.30729.9035", "winsxs": {"dir_pat" : "msil_system.web.extensions", "file_pat":"(?i)^system\.web\.extensions\.dll$", "max_version": "3.5.30729.9999"}}, {"cum": 4470502}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.extensions.dll", "version": "4.7.3282.0"}, {"cum": 4470502}]
  ],
  # January 2019
  "01_2019" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8801", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480062, "sec":  4480084}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8801", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480062, "sec": 4480084}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36490"}, {"cum": 4480059, "sec": 4480076}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480055, "sec": 4480072}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8801", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480063, "sec": 4480085}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36480"}, {"cum": 4480059, "sec": 4480076}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480055, "sec": 4480072}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480055, "sec": 4480072}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480055, "sec": 4480072}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480055, "sec": 4480072}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480055, "sec": 4480072}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480055, "sec": 4480072}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8801", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480061, "sec": 4480083}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36490"}, {"cum": 4480058, "sec": 4480075}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480051, "sec": 4480070}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480051, "sec": 4480070}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480051, "sec": 4480070}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480051, "sec": 4480070}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480051, "sec": 4480070}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480051, "sec": 4480070}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8801", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480064, "sec": 4480086}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36490"}, {"cum": 4480057, "sec": 4480074}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480054, "sec": 4480071}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480054, "sec": 4480071}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480054, "sec": 4480071}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480054, "sec": 4480071}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480054, "sec": 4480071}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480054, "sec": 4480071}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8801", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480962}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1720.0"}, {"cum": 4480962}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1720.0"}, {"cum": 4480962}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1720.0"}, {"cum": 4480962}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8801", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480961}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480961}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480961}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480961}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480961}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8810", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480973}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480973}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480973}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480973}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8836", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480978}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480978}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480978}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8938", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480966}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480966}],
        # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
         [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8938", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4480056}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3314.0"}, {"cum": 4480056}]
  ],
  # February 2019
  "02_2019" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8803", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4483457, "sec":  4483482}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8803", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4483457, "sec": 4483482}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36520"}, {"cum": 4483455, "sec": 4483474}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483451, "sec": 4483470}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8803", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4483458, "sec": 4483483}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36520"}, {"cum": 4483455, "sec": 4483474}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483451, "sec": 4483470}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483451, "sec": 4483470}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483451, "sec": 4483470}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483451, "sec": 4483470}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483451, "sec": 4483470}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483451, "sec": 4483470}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8803", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4483456, "sec": 4483481}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36520"}, {"cum": 4483454, "sec": 4483473}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483449, "sec": 4483468}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483449, "sec": 4483468}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483449, "sec": 4483468}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483449, "sec": 4483468}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483449, "sec": 4483468}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483449, "sec": 4483468}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8803", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4483459, "sec": 4483484}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36520"}, {"cum": 4483453, "sec": 4483472}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483450, "sec": 4483469}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483450, "sec": 4483469}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483450, "sec": 4483469}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483450, "sec": 4483469}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483450, "sec": 4483469}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483450, "sec": 4483469}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8803", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4487018}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1730.0"}, {"cum": 4487018}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8803", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4487026}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487026}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487026}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487026}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487026}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8811", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4487020}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487020}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487020}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487020}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8837", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4486996}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4486996}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4486996}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8939", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4487017}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4487017}],
        # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.9037", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4483452}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3353.0"}, {"cum": 4483452}]
  ],
  # May 2019
  "05_2019" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8806", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4495604, "sec":  4495609}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8806", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4495604, "sec":  4495609}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36543", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.0.30319.9999.0"}}, {"cum": 4495596, "sec": 4495593}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0"}, {"cum": 4495588, "sec": 4495587}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8806", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4495606, "sec": 4495612}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36543", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.0.30319.9999.0"}}, {"cum": 4495596, "sec": 4495593}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495588, "sec": 4495587}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495588, "sec": 4495587}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495588, "sec": 4495587}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495588, "sec": 4495587}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495588, "sec": 4495587}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495588, "sec": 4495587}],
        [{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495626, "sec": 4495627}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8806", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4495602, "sec": 4495607}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36543", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.0.30319.9999.0"}}, {"cum": 4495594, "sec": 4495591}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495582, "sec": 4495584}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495582, "sec": 4495584}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495582, "sec": 4495584}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495582, "sec": 4495584}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495582, "sec": 4495584}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495582, "sec": 4495584}],
        [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495622, "sec": 4495623}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8806", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4495608, "sec": 4495615}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36543", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.0.30319.9999.0"}}, {"cum": 4495592, "sec": 4495589}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495585, "sec": 4495586}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495585, "sec": 4495586}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495585, "sec": 4495586}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495585, "sec": 4495586}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495585, "sec": 4495586}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495585, "sec": 4495586}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495624, "sec": 4495625}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8806", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4499154}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1751.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4499154}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8806", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4494440}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4494440}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4494440}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4494440}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4494440}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495610}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8813", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4499181}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4499181}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4499181}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4499181}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495611}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8839", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4499179}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4499179}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4499179}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495613}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8941", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4499167}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4499167}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495616}],
        # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.9040", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4495590}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.3416.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4495590}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.8.3801.0", "winsxs": {"dir_pat" : "msil_system_b77a5c561934e089", "file_pat":"(?i)^system\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4495618}]
  ],
  # July 2019
  "07_2019" : [
     # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8826", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507003, "sec":  4506975}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8826", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507003, "sec":  4506975}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36566", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4507001, "sec": 4506966}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0"}, {"cum": 4506997, "sec": 4506963}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8826", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507004, "sec": 4506976}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36543", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4507001, "sec": 4506966}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506997, "sec": 4506963}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506997, "sec": 4506963}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506997, "sec": 4506963}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506997, "sec": 4506963}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506997, "sec": 4506963}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506997, "sec": 4506963}],
        [{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506994, "sec": 4506956}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8826", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507002, "sec": 4506974}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36566", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4507000, "sec": 4506965}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506995, "sec": 4506961}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506995, "sec": 4506961}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506995, "sec": 4506961}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506995, "sec": 4506961}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506995, "sec": 4506961}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506995, "sec": 4506961}],
        [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506992, "sec": 4506954}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8826", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507005, "sec": 4506977}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36566", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4506999, "sec": 4506964}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506996, "sec": 4506962}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506996, "sec": 4506962}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506996, "sec": 4506962}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506996, "sec": 4506962}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506996, "sec": 4506962}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506996, "sec": 4506962}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506993, "sec": 4506955}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8826", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507458}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.6.1760.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4507458}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8826", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507460}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507460}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507460}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507460}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507460}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506986}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8809", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507450}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507450}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507450}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507450}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506987}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8842", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507455}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507455}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507455}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506988}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8938", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507435}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4507435}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506989}],
        # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.9040", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4506998}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4506998}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506990}],
        # Windows 10 1903 Update (18362)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.9138", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4506991}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.3825.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4506991}]
  ],
# September 2019
  "09_2019" : [
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.8810", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4514370, "sec": 4514349}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.0.30319.36575", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4514368, "sec": 4514342}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514363, "sec": 4514337}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514363, "sec": 4514337}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514363, "sec": 4514337}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514363, "sec": 4514337}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514363, "sec": 4514337}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514363, "sec": 4514337}],
        [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514360, "sec": 4514330}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.8810", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4514371, "sec": 4514350}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.0.30319.36575", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4514367, "sec": 4514341}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514364, "sec": 4514338}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514364, "sec": 4514338}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514364, "sec": 4514338}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514364, "sec": 4514338}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514364, "sec": 4514338}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514364, "sec": 4514338}],
        [{".net_version":"4.8", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514361, "sec": 4514331}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.8810", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4516070}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.6.1780.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4516070}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.8810", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4516044}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516044}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516044}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516044}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516044}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514354}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.8815", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4516068}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516068}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516068}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516068}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514355}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.8841", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4516066}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516066}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516066}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514356}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.8943", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4516058}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4516058}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514357}],
        # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.9043", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4514366}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.7.3460.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4514366}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514358}],
        # Windows 10 1903 Update (18362) / Windows Server, version 1903 (Server Core installation)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "mscorlib.dll", "version": "2.0.50727.9148", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4514359}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "mscorlib.dll", "version": "4.8.4010.0", "winsxs": {"dir_pat" : "mscorlib_b77a5c561934e089", "file_pat":"(?i)^mscorlib\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4514359}]
  ],
# January 2020
  "01_2020" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8833", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4532944, "sec":  4532959}],
        [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8833", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4507003, "sec":  4506975}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36577", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum":4532929, "sec": 4532964}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0"}, {"cum": 4532932, "sec": 4532971}],

        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8833", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4532945, "sec": 4532960}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36577", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4532929, "sec": 4532964}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532932, "sec": 4532971}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532932, "sec": 4532971}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532932, "sec": 4532971}],
        [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532932, "sec": 4532971}],
        [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532932, "sec": 4532971}],
        [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532932, "sec": 4532971}],
        [{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532941, "sec": 4532952}],

        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8833", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4532943, "sec": 4532958}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36577", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4532928, "sec": 4532963}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532930, "sec": 4532969}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532930, "sec": 4532969}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532930, "sec": 4532969}],
        [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532930, "sec": 4532969}],
        [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532930, "sec": 4532969}],
        [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532930, "sec": 4532969}],
        [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532939, "sec": 4532950}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8833", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4532946, "sec": 4532961}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.0.30319.36577", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4532927, "sec": 4532962}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532931, "sec": 4532970}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532931, "sec": 4532970}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532931, "sec": 4532970}],
        [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532931, "sec": 4532970}],
        [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532931, "sec": 4532970}],
        [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3440.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system.workflow.runtime.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532931, "sec": 4532970}],
        [{".net_version":"4.8", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532940, "sec": 4532951}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8833", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4534306}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.6.1795.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4534306}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8833", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4534271}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534271}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534271}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534271}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534271}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532933}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8813", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4534296}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534296}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534296}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534296}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532934}],
        # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8846", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4534276}],
        [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534276}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534276}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532935}],
        # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.8942", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4534293}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4534293}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532936}],
        # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.9043", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4532947}],
        [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.7.3570.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4532947}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532937}],
        # Windows 10 1903 Update (18362)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.workflow.runtime.dll", "version": "3.0.4203.9143", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "3.0.4203.9999"}}, {"cum": 4532938}],
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532938}],
        # Windows 10 1909 Update (18362)
        [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.workflow.runtime.dll", "version": "4.8.4110.0", "winsxs": {"dir_pat" : "system.workflow.runtime_31bf3856ad364e35", "file_pat":"(?i)^system\.workflow\.runtime\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4532938}]
  ],
  # May 2020
  "05_2020" : [
    # 2008 Server SP2
    [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8841", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum":4552939 , "sec":4552964}],
    [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8841", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4552939, "sec":  4552964}],
    [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.0.30319.36627", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4552920, "sec": 4552952}],
    [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0"}, {"cum": 4552919, "sec": 4552951}],
    # Windows 7 SP1 / Server 2008 R2 SP1
    [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8841", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4552940, "sec": 4552965}],
    [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.0.30319.36627", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4552920, "sec": 4552952}],
    [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552919, "sec": 4552951}],
    [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552919, "sec": 4552951}],
    [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552919, "sec": 4552951}],
    [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552919, "sec": 4552951}],
    [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552919, "sec": 4552951}],
    [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552919, "sec": 4552951}],
    [{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552921, "sec": 4552953}],
    # Server 2012
    [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8841", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4552979, "sec": 4552963}],
    [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.0.30319.36627", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4552947, "sec": 4552968}],
    [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552922, "sec": 4552958}],
    [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552922, "sec": 4552958}],
    [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552922, "sec": 4552958}],
    [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552922, "sec": 4552958}],
    [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552922, "sec": 4552958}],
    [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552922, "sec": 4552958}],
    [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552932, "sec": 4552961}],
    # Windows 8.1 / Server 2012 R2
    [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8841", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4552982, "sec": 4552966}],
    [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.0.30319.36627", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4552946, "sec": 4552967}],
    [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552923, "sec": 4552959}],
    [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552923, "sec": 4552959}],
    [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552923, "sec": 4552959}],
    [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552923, "sec": 4552959}],
    [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552923, "sec": 4552959}],
    [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system.runtime.serialization.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552923, "sec": 4552959}],
    [{".net_version":"4.8", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552933, "sec": 4552962}],
    # Windows 10 RTM (10240)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8841", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4556826}],
    [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.6.1810.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4556826}],
    # Windows 10 1607 Anniversary Update (14393) / Server 2016
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8841", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4556813}],
    [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556813}],
    [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556813}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556813}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556813}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552926}],
    # Windows 10 1703 Creator's Update (15063)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8815", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4556804}],
    [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556804}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556804}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556804}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552927}],
    # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8848", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4556812}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556812}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556812}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552928}],
    # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.8944", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4556807}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4556807}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552929}],
    # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.9045", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4552924}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.7.3620.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4552924}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552930}],
    # Windows 10 1903 Update (18362)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.9149", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4552931}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552931}],
    # Windows 10 1909 Update (18363)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.runtime.serialization.dll", "version": "3.0.4506.9149", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "3.0.4506.9999"}}, {"cum": 4552931}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.runtime.serialization.dll", "version": "4.8.4180.0", "winsxs": {"dir_pat" : "system.runtime.serialization_b77a5c561934e089", "file_pat":"(?i)^system\.runtime\.serialization\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4552931}]
  ],
  # July 2020
  "07_2020" : [
    # 2008 Server SP2
    [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565611, "sec": 4565578}],
    [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565611, "sec": 4565578}],
    [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.0.30319.36645", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4565616, "sec": 4565583}],
    [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0"}, {"cum": 4565623, "sec": 4565586}],
    # Windows 7 SP1 / Server 2008 R2 SP1
    [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565612, "sec": 4565579}],
    [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.0.30319.36645", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4565616, "sec": 4565583}],
    [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565623, "sec": 4565586}],
    [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565623, "sec": 4565586}],
    [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565623, "sec": 4565586}],
    [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565623, "sec": 4565586}],
    [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565623, "sec": 4565586}],
    [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565623, "sec": 4565586}],
    [{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565636, "sec": 4565589}],
    # Server 2012
    [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565610, "sec": 4565577}],
    [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.0.30319.36645", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4565615, "sec": 4565582}],
    [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565621, "sec": 4565584}],
    [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565621, "sec": 4565584}],
    [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565621, "sec": 4565584}],
    [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565621, "sec": 4565584}],
    [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565621, "sec": 4565584}],
    [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565621, "sec": 4565584}],
    [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565634, "sec": 4565587}],
    # Windows 8.1 / Server 2012 R2
    [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565613, "sec": 4565580}],
    [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.0.30319.36645", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4565614, "sec": 4565581}],
    [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565622, "sec": 4565585}],
    [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565622, "sec": 4565585}],
    [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565622, "sec": 4565585}],
    [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565622, "sec": 4565585}],
    [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565622, "sec": 4565585}],
    [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565622, "sec": 4565585}],
    [{".net_version":"4.8", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565635, "sec": 4565588}],
    # Windows 10 RTM (10240)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565513}],
    [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.6.1820.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4565513}],
    # Windows 10 1607 Anniversary Update (14393) / Server 2016
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565511}],
    [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565511}],
    [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565511}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565511}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565511}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565628}],
    # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565508}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565508}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565508}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565630}],
    # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.8949", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565489}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565489}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565631}],
    # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.9046", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565625}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.7.3630.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4565625}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565632}],
    # Windows 10 1903 Update (18362)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.9153", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565633}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565633}],
    # Windows 10 1909 Update (18363)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.9153", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565633}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565633}],
    # Windows 10 2004 Update (19041)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "19041", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.configuration.dll", "version": "2.0.50727.9153", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4565627}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "19041", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.configuration.dll", "version": "4.8.4190.0", "winsxs": {"dir_pat" : "msil_system.configuration_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.configuration\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4565627}]
  ],
  # August 2020
  "08_2020" : [
    # 2008 Server SP2
    [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569766, "sec": 4569735}],
    [{".net_version":"3.0", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569766, "sec": 4569735}],
    [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.0.30319.36660", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4569780, "sec": 4569743}],
    [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0"}, {"cum": 4569775, "sec": 4569740}],
    # Windows 7 SP1 / Server 2008 R2 SP1
    [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569767, "sec": 4569736}],
    [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.0.30319.36660", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4569780, "sec": 4569743}],
    [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569775, "sec": 4569740}],
    [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569775, "sec": 4569740}],
    [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569775, "sec": 4569740}],
    [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569775, "sec": 4569740}],
    [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569775, "sec": 4569740}],
    [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569775, "sec": 4569740}],
    [{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569754, "sec": 4569733}],
    # Server 2012
    [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569765, "sec": 4569734}],
    [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.0.30319.36660", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4569779, "sec": 4569742}],
    [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569773, "sec": 4569738}],
    [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569773, "sec": 4569738}],
    [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569773, "sec": 4569738}],
    [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569773, "sec": 4569738}],
    [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569773, "sec": 4569738}],
    [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569773, "sec": 4569738}],
    [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569752, "sec": 4569731}],
    # Windows 8.1 / Server 2012 R2
    [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569768, "sec": 4569737}],
    [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.0.30319.36660", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4569778, "sec": 4569741}],
    [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569774, "sec": 4569739}],
    [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569774, "sec": 4569739}],
    [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569774, "sec": 4569739}],
    [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569774, "sec": 4569739}],
    [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569774, "sec": 4569739}],
    [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569774, "sec": 4569739}],
    [{".net_version":"4.8", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4120.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569753, "sec": 4569732}],
    # Windows 10 RTM (10240)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4571692}],
    [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.6.1821.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4571692}],
    # Windows 10 1607 Anniversary Update (14393) / Server 2016
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4571694}],
    [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569746}],
    # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4571741}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571741}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571741}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569748}],
    # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.8951", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4571709}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571709}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569749}],
    # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.9047", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569776}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.7.3650.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4569776}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569750}],
    # Windows 10 1903 Update (18362)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.9154", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569751}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569751}],
    # Windows 10 1909 Update (18363)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.9154", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569751}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569751}],
    # Windows 10 2004 Update (19041)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "19041", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.web.dll", "version": "2.0.50727.9154", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4569745}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "19041", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.web.dll", "version": "4.8.4210.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.web\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4569745}]
  ],
  # Sep 2020
  "09_2020" : [
    # Windows 7 SP1 / Server 2008 R2 SP1
    [{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576487, "sec": 4576490}],
    # Server 2012
    [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576485, "sec": 4576488}],
    # Windows 8.1 / Server 2012 R2
    [{".net_version":"4.8", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576486, "sec": 4576489}],
    # Windows 10 1607 Anniversary Update (14393) / Server 2016
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576479}],
    # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576481}],
    # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576482}],
    # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576483}],
    # Windows 10 1903 Update (18362)
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576484}],
    # Windows 10 1909 Update (18363)
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576484}],
    # Windows 10 2004 Update (19041)
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "19041", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.deployment.dll", "version": "4.8.4240.0", "winsxs": {"dir_pat" : "system.deployment_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.deployment\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4576478}]
  ],
  # Oct 2020
  "10_2020" : [
    # Windows 7 SP1 / Server 2008 R2 SP1
    [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8953", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4579977, "sec": 4580467}],
    [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.0.30319.36680", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4579977, "sec": 4580467}],
    [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579977, "sec": 4580467}],
    [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579977, "sec": 4580467}],
    [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.web_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579977, "sec": 4580467}],
    [{".net_version":"4.7", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579977, "sec": 4580467}],
    [{".net_version":"4.7.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.secutiry\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579977, "sec": 4580467}],
    [{".net_version":"4.7.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579977, "sec": 4580467}],
    # This patch is not installing on win7/2k8r2, so leaving out for now.
    #[{".net_version":"4.8", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4260.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4579977, "sec": 4578990}],
    # Server 2012
    [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8952", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.0.30319.36680", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.7", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.7.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.7.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579978, "sec": 4580468}],
    [{".net_version":"4.8", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4260.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4579978, "sec": 4580468}],
    # Windows 8.1 / Server 2012 R2
    [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8952", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.0.30319.36680", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.0.30319.9999"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.7", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.7.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.7.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3700.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4579979, "sec": 4580469}],
    [{".net_version":"4.8", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4160.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4579979, "sec": 4580469}],
    # Windows 10 RTM (10240)
    # Leaving out for. Patch links are incorrect.
    #[{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8953", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4580327}],
    #[{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.6.1831.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.6.9999.0"}}, {"cum": 4580327}],
    # Windows 10 1607 Anniversary Update (14393) / Server 2016
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8953", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4580346}],
    [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    #[{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4571694}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4261.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4578969}],
    # Windows 10 1709 Fall Creators Update (16299) / Windows Server 1709
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8953", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4580328}],
    [{".net_version":"4.7.1", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4580328}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4580328}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "16299", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4261.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4578971}],
    # Windows 10 1803 April 2018 Update (17134) / Windows Server 1803
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.8953", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4580330}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4580330}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "177134", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4261.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4578972}],
    # Windows 10 1809 October(?) 2018 Update (17763) / Windows Server 1809 / Windows Server 2019
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.9049", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4578966}],
    [{".net_version":"4.7.2", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.7.3701.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.7.9999.0"}}, {"cum": 4578966}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "17763", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4261.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4578973}],
    # Windows 10 1903 Update (18362)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.9156", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4578974}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18362", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4261.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4578974}],
    # Windows 10 1909 Update (18363)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.9156", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4578974}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "18363", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4261.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4578974}],
    # Windows 10 2004 Update (19041)
    [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "19041", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.security.dll", "version": "2.0.50727.9156", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "2.0.50727.9999"}}, {"cum": 4578968}],
    [{".net_version":"4.8", "os":'10', "sp":0, "os_build": "19041", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.security.dll", "version": "4.8.4261.0", "winsxs": {"dir_pat" : "system.security_b03f5f7f11d50a3a", "file_pat":"(?i)^system\.security\.dll$", "max_version": "4.8.9999.0"}}, {"cum": 4578968}]
  ],
  '02_2021': [
    # Windows 10, version 20H2 and Windows Server, version 20H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601050}],
    # Windows 10 2004 and Windows Server, version 2004
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19041', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601050}],
    # Windows 10 1909 and Windows Server, version 1909
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '18362', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601056}],
    # Windows 10 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601060}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601055}],
    # Windows 10 1803 (April 2018 Update)
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17134', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601054}],
    # Windows 10 1703 (Creators Update)
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '15063', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601052}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601051}],
    # Windows 8.1, Windows RT 8.1 and Windows Server 2012 R2
    [{'.net_version':'4.6', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601048, 'sec': 4601094}],
    [{'.net_version':'4.6.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601048, 'sec': 4601094}],
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601048, 'sec': 4601094}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601048, 'sec': 4601094}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601048, 'sec': 4601094}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601048, 'sec': 4601094}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601058, 'sec': 4601092}],
    # Windows Server 2012
    [{'.net_version':'4.6', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600957, 'sec': 4601093}],
    [{'.net_version':'4.6.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600957, 'sec': 4601093}],
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600957, 'sec': 4601093}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600957, 'sec': 4601093}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600957, 'sec': 4601093}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600957, 'sec': 4601093}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4601057, 'sec': 4601091}],
    # Windows 7 SP1 and Windows Server 2008 R2 SP1
    [{'.net_version':'4.6', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600945, 'sec': 4601090}],
    [{'.net_version':'4.6.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600945, 'sec': 4601090}],
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600945, 'sec': 4601090}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600945, 'sec': 4601090}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600945, 'sec': 4601090}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600945, 'sec': 4601090}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4330.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600944, 'sec': 4601089}],
    # Windows Server 2008
    [{'.net_version':'4.6', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3770.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 4600945, 'sec': 4601090}],
  ],
  '01_2022': [
    # Windows 11
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9160', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008880}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008880}],
    # Microsoft server operating systems version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9160', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008882}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008882}],
    # Windows 10 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9160', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008876}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008876}],
    # Windows 10 21H1
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9160', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008876}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008876}],
    # Windows 10, version 20H2 and Windows Server, version 20H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9160', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008876}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008876}],
    # Windows 10 1909
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '18362', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9160', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008879}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '18362', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.runtime.serialization.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.runtime.serialization_b77a5c561934e089', 'file_pat':"(?i)^system\.runtime\.serialization\.dll$", 'max_version': '4.999'}}, {'cum': 5008879}],
    # Windows 10 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9050', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008878}],
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008873}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008878}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.runtime.serialization.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.runtime.serialization_b77a5c561934e089', 'file_pat':"(?i)^system\.runtime\.serialization\.dll$", 'max_version': '4.999'}}, {'cum': 5008877}],
    # Windows 8.1, Windows RT 8.1 and Windows Server 2012 R2
    [{'.net_version':'3.5', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8955', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008868, 'sec': 5008891}],
    [{'.net_version':'4.5.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36720', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008870, 'sec': 5008893}],
    [{'.net_version':'4.6', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008875, 'sec': 5008895}],
    [{'.net_version':'4.6.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008875, 'sec': 5008895}],
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008875, 'sec': 5008895}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008875, 'sec': 5008895}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008875, 'sec': 5008895}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008875, 'sec': 5008895}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008883, 'sec': 5008897}],
    # Windows Server 2012
    [{'.net_version':'3.5', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8955', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008865, 'sec': 5008888}],
    [{'.net_version':'4.5.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36720', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008869, 'sec': 5008892}],
    [{'.net_version':'4.6', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008874, 'sec': 5008894}],
    [{'.net_version':'4.6.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008874, 'sec': 5008894}],
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008874, 'sec': 5008894}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008874, 'sec': 5008894}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008874, 'sec': 5008894}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008874, 'sec': 5008894}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008881, 'sec': 5008896}],
    # Windows 7 SP1 and Windows Server 2008 R2 SP1
    [{'.net_version':'3.5.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8955', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008867, 'sec': 5008890}],
    [{'.net_version':'4.5.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36720', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008860, 'sec': 5008887}],
    [{'.net_version':'4.6', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008859, 'sec': 5008886}],
    [{'.net_version':'4.6.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008859, 'sec': 5008886}],
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008859, 'sec': 5008886}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008859, 'sec': 5008886}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008859, 'sec': 5008886}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008859, 'sec': 5008886}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4465.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008858, 'sec': 5008885}],
    # Windows Server 2008
    [{'.net_version':'2.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8955', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008866, 'sec': 5008889}],
    [{'.net_version':'3.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8955', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5008866, 'sec': 5008889}],
    [{'.net_version':'4.5.2', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36720', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008860, 'sec': 5008887}],
    [{'.net_version':'4.6', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3905.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5008859, 'sec': 5008886}],
  ],
  '04_2022': [
    # Windows 11
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9161', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012121}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012121}],
    # Microsoft server operating systems version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9161', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012123}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012123}],
    # Windows 10 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9161', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012117}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012117}],
    # Windows 10 21H1
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9161', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012117}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012117}],
    # Windows 10, version 20H2 and Windows Server, version 20H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9161', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012117}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012117}],
    # Windows 10 1909
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '18362', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9161', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012120}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '18362', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012120}],
    # Windows 10 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.9051', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012128}],
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012128}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012119}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012118}],
    # Windows 8.1, Windows RT 8.1 and Windows Server 2012 R2
    [{'.net_version':'3.5', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8962', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012139, 'sec': 5012152}],
    [{'.net_version':'4.5.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36730', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012142, 'sec': 5012155}],
    [{'.net_version':'4.6', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012130, 'sec': 5012147}],
    [{'.net_version':'4.6.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012130, 'sec': 5012147}],
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012130, 'sec': 5012147}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012130, 'sec': 5012147}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012130, 'sec': 5012147}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012130, 'sec': 5012147}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012124, 'sec': 5012144}],
    # Windows Server 2012
    [{'.net_version':'3.5', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8962', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012136, 'sec': 5012149}],
    [{'.net_version':'4.5.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36730', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012140, 'sec': 5012153}],
    [{'.net_version':'4.6', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012129, 'sec': 5012146}],
    [{'.net_version':'4.6.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012129, 'sec': 5012146}],
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012129, 'sec': 5012146}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012129, 'sec': 5012146}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012129, 'sec': 5012146}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012129, 'sec': 5012146}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012122, 'sec': 5012143}],
    # Windows 7 SP1 and Windows Server 2008 R2 SP1
    [{'.net_version':'3.5.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8962', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012138, 'sec': 5012151}],
    [{'.net_version':'4.5.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36730', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012141, 'sec': 5012154}],
    [{'.net_version':'4.6', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012131, 'sec': 5012148}],
    [{'.net_version':'4.6.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012131, 'sec': 5012148}],
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012131, 'sec': 5012148}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012131, 'sec': 5012148}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012131, 'sec': 5012148}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012131, 'sec': 5012148}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.8.4494.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012125, 'sec': 5012145}],
    # Windows Server 2008
    [{'.net_version':'2.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8962', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012137, 'sec': 5012150}],
    [{'.net_version':'3.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.web.dll', 'version': '2.0.50727.8962', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5012137, 'sec': 5012150}],
    [{'.net_version':'4.5.2', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.0.30319.36730', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012141, 'sec': 5012154}],
    [{'.net_version':'4.6', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.web.dll', 'version': '4.7.3930.0', 'winsxs': {'dir_pat' : 'system.web_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.web\.dll$", 'max_version': '4.999'}}, {'cum': 5012131, 'sec': 5012148}],
  ],
  '05_2022': [
    # Windows 11
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.directoryservices.dll', 'version': '2.0.50727.9162', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013628}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4501.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013628}],
    # Microsoft server operating systems version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.directoryservices.dll', 'version': '2.0.50727.9162', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013630}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4501.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013630}],
    # Windows 10 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.directoryservices.dll', 'version': '2.0.50727.9162', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013624}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4501.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013624}],
    # Windows 10 21H1
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.directoryservices.dll', 'version': '2.0.50727.9162', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013624}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4501.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013624}],
    # Windows 10, version 20H2 and Windows Server, version 20H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.directoryservices.dll', 'version': '2.0.50727.9162', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013624}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4501.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013624}],
    # Windows 10 1909
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '18362', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.directoryservices.dll', 'version': '2.0.50727.9164', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013627}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '18362', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4510.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013627}],
    # Windows 10 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.directoryservices.dll', 'version': '2.0.50727.9052', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013641}],
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.7.3941.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013641}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4501.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013626}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.directoryservices.dll', 'version': '4.8.4510.0', 'winsxs': {'dir_pat' : 'system.directoryservices_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.directoryservices\.dll$", 'max_version': '4.999'}}, {'cum': 5013625}],
    # Windows 8.1, Windows RT 8.1 and Windows Server 2012 R2
    [{'.net_version':'3.5', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8964', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013638, 'sec': 5013621}],
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013643, 'sec': 5013623}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013643, 'sec': 5013623}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013643, 'sec': 5013623}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013643, 'sec': 5013623}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4510.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013631, 'sec': 5013616}],
    # Windows Server 2012
    [{'.net_version':'3.5', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8964', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013635, 'sec': 5013618}],
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013642, 'sec': 5013622}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013642, 'sec': 5013622}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013642, 'sec': 5013622}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013642, 'sec': 5013622}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4510.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013629, 'sec': 5013615}],
    # Windows 7 SP1 and Windows Server 2008 R2 SP1
    [{'.net_version':'3.5.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8964', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013637, 'sec': 5013620}],
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013644, 'sec': 5013612}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013644, 'sec': 5013612}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013644, 'sec': 5013612}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013644, 'sec': 5013612}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4510.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013632, 'sec': 5013617}],
    # Windows Server 2008
    [{'.net_version':'2.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8964', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013636, 'sec': 5013619}],
    [{'.net_version':'3.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8964', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5013636, 'sec': 5013619}],
    [{'.net_version':'4.6.2', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.3946.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5013644, 'sec': 5013612}],
  ],
  '09_2022': [
    # Windows 11
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.4550.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017024}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.9082.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017029}],
    # Microsoft server operating systems version 21H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.4550.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017028}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.9082.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017030}],
    # Windows 10 21H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.4550.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017022}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.9082.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017025}],
    # Windows 10 21H1
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.4550.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017022}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.9082.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017025}],
    # Windows 10, version 20H2 and Windows Server, version 20H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.4550.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017022}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.windows.forms.dll', 'version': '4.8.9082.0', 'winsxs': {'dir_pat' : 'system.windows.forms_b77a5c561934e089', 'file_pat':"(?i)^system\.windows\.forms\.dll$", 'max_version': '4.999'}}, {'cum': 5017025}],
  ],
  '11_2022': [
    # Windows 11, version 22H2
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9105.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020622}],
    # Windows 11, version 21H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4579.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020617}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9105.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020624}],
    # Microsoft server operating system, version 22H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20349', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4579.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020619}],
    # Microsoft server operating system, version 21H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4579.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020619}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9105.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020632}],
    # Windows 10, version 22H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4579.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020613}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9105.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020623}],
    # Windows 10, version 21H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4579.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020613}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9105.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020623}],
    # Windows 10, version 21H1
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4579.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020613}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9105.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020623}],
    # Windows 10, version 20H2
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4579.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020613}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9105.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020623}],
    # Windows 10, version 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020627}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4585.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020615}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4585.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020614}],
    # Windows 8.1, Windows RT 8.1 and Windows Server 2012 R2
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020629, 'sec': 5020611}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020629, 'sec': 5020611}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020629, 'sec': 5020611}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020629, 'sec': 5020611}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.8.4585.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020620, 'sec': 5020608}],
    # Windows Server 2012
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020628, 'sec': 5020610}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020628, 'sec': 5020610}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020628, 'sec': 5020610}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020628, 'sec': 5020610}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.8.4585.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020618, 'sec': 5020606}],
    # Windows 7 SP1 and Windows Server 2008 R2 SP1
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020630, 'sec': 5020612}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020630, 'sec': 5020612}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020630, 'sec': 5020612}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020630, 'sec': 5020612}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.8.4585.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020621, 'sec': 5020609}],
    # Windows Server 2008 SP2
    [{'.net_version':'4.6.2', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4005.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5020630, 'sec': 5020612}]
  ],
  '12_2022': [
    # Windows 11, version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020880}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9115.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020880}],
    # Windows 11, version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020882}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020875}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9115.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020882}],
    # Microsoft server operating system, version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '20349', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020877}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20349', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020877}],
    # Microsoft server operating system version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020877}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020877}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9115.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020883}],
    # Windows 10 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020881}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020872}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9115.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020881}],
    # Windows 10 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020881}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020872}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9115.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020881}],
    # Windows 10 21H1
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020881}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020872}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19043', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9115.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020881}],
    # Windows 10 Version 20H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9155', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020881}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020872}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9115.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020881}],
    # Windows 10 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.9054', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020866}],
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020866}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020874}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020873}],
    # Windows 8.1, Windows RT 8.1 and Windows Server 2012 R2
    [{'.net_version':'3.5', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8953', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020862, 'sec': 5020897}],
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020868, 'sec': 5020899}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020868, 'sec': 5020899}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020868, 'sec': 5020899}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020868, 'sec': 5020899}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020878, 'sec': 5020902}],
    # Windows Server 2012
    [{'.net_version':'3.5', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8953', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020859, 'sec': 5020894}],
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020867, 'sec': 5020898}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020867, 'sec': 5020898}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020867, 'sec': 5020898}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020867, 'sec': 5020898}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020876, 'sec': 5020901}],
    # Windows 7 SP1 and Windows Server 2008 R2 SP1
    [{'.net_version':'3.5.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8953', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020861, 'sec': 5020896}],
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020869, 'sec': 5020900}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020869, 'sec': 5020900}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020869, 'sec': 5020900}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020869, 'sec': 5020900}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4590.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020879, 'sec': 5020903}],
    # Windows Server 2008
    [{'.net_version':'2.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8953', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020860, 'sec': 5020895}],
    [{'.net_version':'3.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8953', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5020860, 'sec': 5020895}],
    [{'.net_version':'4.6.2', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4010.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5020869, 'sec': 5020900}],
  ],
  '02_2023': [
    # Windows 11, version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9168', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022497}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9139.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022497}],
    # Windows 11, version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9168', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022505}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022505}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9139.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022499}],
    # Microsoft server operating system, version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9168', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022507}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022507}],
    # Microsoft server operating system version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9168', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022507}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022507}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9139.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022501}],
    # Windows 10 Version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9168', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022502}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022502}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9139.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022498}],
    # Windows 10 Version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9168', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022502}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022502}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9139.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022498}],
    # Windows 10 Version 20H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9168', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022502}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022502}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19042', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9139.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022498}],
    # Windows 10 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.9055', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022504}],
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022511}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022504}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5022503}],
    # Windows Embedded 8.1 and Windows Server 2012 R2
    [{'.net_version':'3.5', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8966', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022525, 'sec': 5022531}],
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022513, 'sec': 5022524}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022513, 'sec': 5022524}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022513, 'sec': 5022524}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022513, 'sec': 5022524}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022508, 'sec': 5022516}],
    # Windows Embedded 8 and Windows Server 2012
    [{'.net_version':'3.5', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8966', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022574, 'sec': 5022575}],
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022512, 'sec': 5022522}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022512, 'sec': 5022522}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022512, 'sec': 5022522}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022512, 'sec': 5022522}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022506, 'sec': 5022514}],
    # Windows Embedded 7 Standard and Windows Server 2008 R2 SP1
    [{'.net_version':'3.5.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8966', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022523, 'sec': 5022530}],
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022515, 'sec': 5022526}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022515, 'sec': 5022526}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022515, 'sec': 5022526}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022515, 'sec': 5022526}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.8.4614.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022509, 'sec': 5022520}],
    # Windows Server 2008
    [{'.net_version':'2.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8966', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022521, 'sec': 5022529}],
    [{'.net_version':'3.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'mscorlib.dll', 'version': '2.0.50727.8966', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5022521, 'sec': 5022529}],
    [{'.net_version':'4.6.2', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'mscorlib.dll', 'version': '4.7.4038.0', 'winsxs': {'dir_pat' : 'mscorlib_b77a5c561934e089', 'file_pat':"(?i)^mscorlib\.dll$", 'max_version': '4.999'}}, {'cum': 5022515, 'sec': 5022526}]
  ],
  '06_2023': [
    # Windows 11, version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.9171', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027119}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9166.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027119}],
    # Windows 11, version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.9171', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027125}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027125}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '22000', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9166.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027118}],
    # Microsoft server operating system, version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.9171', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027127}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '22621', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027127}],
    # Microsoft server operating system version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.9171', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027127}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027127}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '20348', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9166.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027121}],
    # Windows 10, version 22H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.9171', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027122}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027122}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19045', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9166.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027117}],
    # Windows 10, version 21H2
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.9171', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027122}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027122}],
    [{'.net_version':'4.8.1', 'os':'10', 'sp':0, 'os_build': '19044', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.9166.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027117}],
    # Windows 10 1809 (October 2018 Update) and Windows Server 2019
    [{'.net_version':'3.5', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.9058', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027131}],
    [{'.net_version':'4.7.2', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027131}],
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '17763', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027124}],
    # Windows 10 1607 (Anniversary Update) and Windows Server 2016
    [{'.net_version':'4.8', 'os':'10', 'sp':0, 'os_build': '14393', 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027123}],
    # Windows Embedded 8.1 and Windows Server 2012 R2
    [{'.net_version':'3.5', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.data.dll', 'version': '2.0.50727.8970', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027141, 'sec': 5027116}],
    [{'.net_version':'4.6.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027133, 'sec': 5027112}],
    [{'.net_version':'4.7', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027133, 'sec': 5027112}],
    [{'.net_version':'4.7.1', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027133, 'sec': 5027112}],
    [{'.net_version':'4.7.2', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027133, 'sec': 5027112}],
    [{'.net_version':'4.8', 'os':'6.3', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027128, 'sec': 5027109}],
    # Windows Embedded 8 and Windows Server 2012
    [{'.net_version':'3.5', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8954', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027138, 'sec': 5027107}],
    [{'.net_version':'4.6.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027132, 'sec': 5027111}],
    [{'.net_version':'4.7', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027132, 'sec': 5027111}],
    [{'.net_version':'4.7.1', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027132, 'sec': 5027111}],
    [{'.net_version':'4.7.2', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027132, 'sec': 5027111}],
    [{'.net_version':'4.8', 'os':'6.2', 'sp':0, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027126, 'sec': 5027108}],
    # Windows Embedded 7 and Windows Server 2008 R2 SP1
    [{'.net_version':'3.5.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8954', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027140, 'sec': 5027115}],
    [{'.net_version':'4.6.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5027134, 'sec': 5027113}],
    [{'.net_version':'4.7', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5027134, 'sec': 5027113}],
    [{'.net_version':'4.7.1', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5027134, 'sec': 5027113}],
    [{'.net_version':'4.7.2', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5027134, 'sec': 5027113}],
    [{'.net_version':'4.8', 'os':'6.1', 'sp':1, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.core.dll', 'version': '4.8.4644.0', 'winsxs': {'dir_pat' : 'system.core_b03f5f7f11d50a3a', 'file_pat':"(?i)^system\.core\.dll$", 'max_version': '4.999'}}, {'cum': 5027129, 'sec': 5027110}],
    # Windows Server 2008
    [{'.net_version':'2.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8954', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027139, 'sec': 5027114}],
    [{'.net_version':'3.0', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v2.0.50727", 'file': 'system.printing.dll', 'version': '3.0.6920.8954', 'winsxs': {'dir_pat' : 'system.printing_31bf3856ad364e35', 'file_pat':"(?i)^system\.printing\.dll$", 'max_version': '3.5.9999'}}, {'cum': 5027139, 'sec': 5027114}],
    [{'.net_version':'4.6.2', 'os':'6.0', 'sp':2, 'path':"\Microsoft.NET\Framework\v4.0.30319", 'file': 'system.data.dll', 'version': '4.7.4050.0', 'winsxs': {'dir_pat' : 'system.data_b77a5c561934e089', 'file_pat':"(?i)^system\.data\.dll$", 'max_version': '4.999'}}, {'cum': 5027134, 'sec': 5027113}],
  ]
};

function rollup_fcheck(path, fix)
{
  var fver, r_code, cmp_result, report;
  
  fver = hotfix_get_fversion(path:path);

  if (isnull(fver) || empty_or_null(fver['error']))
  {
    return {error:HCF_ERR, version:''};
  }

  if (fver['error'] == HCF_OK)
  {
    cmp_result = ver_compare(ver:fver['version'], fix:fix, strict:FALSE);

    if (isnull(cmp_result))
      return {error:HCF_ERR, version:fver['version']};
    else if (cmp_result >= 0)
      return {error:HCF_OK, version:fver['version']};
    else
    {
      report = '  - ' + path + ' has not been patched.\n'
             + '    Remote version : ' + fver['version'] + '\n'
             + '    Should be      : ' + fix + '\n';
      return {error:HCF_OLDER, version:fver['version'], report:report};
    }
  }
  else
  {
    report = '  - An error occured while attempting to check ' + path + '\n'
           +     'Error Code       : ' + fver['error'] + '\n';
    return {error:fver['error'], report:report};
  }
}


function set_rollup_info(rollup, path, fver_arr)
{
  var error, version, report;
  if (isnull(rollup) || isnull(fver_arr) || isnull(path))
    return FALSE;
    
  if (!isnull(fver_arr['error']))
  {
    error = fver_arr['error'];
    replace_kb_item(name:'smb_dotnet_rollup/' + rollup + '/error_code', value:fver_arr['error']);
    replace_kb_item(name:'smb_dotnet_rollup/' + rollup + '/file', value:path);
    if (!isnull(fver_arr['version'])) replace_kb_item(name:'smb_dotnet_rollup/' + rollup + '/file_ver', value:fver_arr['version']);
  
    if (!isnull(fver_arr['report']))
    {
      report = get_kb_item('smb_dotnet_rollup/version_report/' + rollup);
      if (!empty_or_null(report))
        report += fver_arr['report'];
      else
        report = fver_arr['report'];
  
      replace_kb_item(name:'smb_dotnet_rollup/version_report/' + rollup, value:report); 
    }
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}


##
# A wrapper function around hotfix_check_fversion to check if file contains kb rollups
#
# @param file filename of the binary to check for patches
# @param version of the file to compare
# @param absolute path of the file to check
# @param min_version is a cuttoff of the version
# @param bulletin ID in the MSyy-xyz format
# @param kb number (number only) for MSFT KB
# @param product name of the product
# @param channel name of the channel
# @param channel_product name of channel product
# @param channel_version name of channel version
# @param rollup used to format report output
# @param dotnet_ver version of .NET
# @param systemroot path of sys root
# @param winsxs for Windows side-by-side
# @returns the rollup results
##
function is_patched(file, version, &path, min_version, bulletin, kb, product, channel, channel_product, channel_version, rollup, dotnet_ver, systemroot, winsxs)
{
  var ver_report, report_name, report_text;
  var files, none_found, results;
  if (!empty_or_null(path))
  {
    path = strcat(systemroot, path);
    results = hotfix_check_fversion(
      file            : file, 
      version         : version, 
      path            : path, 
      min_version     : min_version, 
      bulletin        : bulletin, 
      kb              : kb, 
      product         : product, 
      channel         : channel, 
      channel_product : channel_product, 
      channel_version : channel_version, 
      rollup_check    : rollup 
    );
  }

  if (results == HCF_OLDER)
  {
    ver_report = hotfix_get_report();
    if (!empty_or_null(ver_report))
    {
      report_text = strstr(ver_report, rollup);
      if (!isnull(report_text))
      {
        # Remove rollup date and format the output for reporting
        report_text = report_text - rollup;
        report_text = report_text - '  - ';
        set_kb_item(name:kb_base+"/version_report/"+rollup+"/"+dotnet_ver,value:report_text);
      }
    }
  }
  # Try winsxs if it's provided
  else if ((results == HCF_NOENT || isnull(results)) && typeof(winsxs) == 'array')
  {
    var basedir = preg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
    files = list_dir(basedir:basedir, level:0, dir_pat:winsxs.dir_pat, file_pat:winsxs.file_pat, max_recurse:1);
    if (!empty_or_null(files))
    {
      results = hotfix_check_winsxs(
        files         : files, 
        versions      : [version], 
        max_versions  : [winsxs.max_version], 
        bulletin      : bulletin, 
        kb            : kb, 
        none_found    : none_found);

      if (none_found) results = HCF_NOENT;
      
      switch (results)
      {
        case HCF_OK:
          path = "\winsxs\*" + winsxs.dir_pat + "*"; # Path pointer
          break;
        case HCF_OLDER:
          ver_report = hotfix_get_report();
          if (!empty_or_null(ver_report))
          {
            report_text = substr(ver_report, '\nKB :');
            if (!isnull(report_text))
            {
              report_name = strcat(kb_base, 'version_report/', rollup, '/', dotnet_ver);
              report_text = report_text - '\nKB :';
              set_kb_item(name:report_name, value:report_text);
            }
          }
          break;
      }
    }
    else
      return HCF_NOENT;
  }
  return results;
}


# Main
var kb_base = "smb_dotnet_rollup";
var app = 'Microsoft .NET Framework';
var cpe = 'cpe:/a:microsoft:.net_framework';
var vendor = 'Microsoft';
var product = '.NET Framework';
var extra = {};
var port = kb_smb_transport();
var registry_kbs = make_array();

var installs = get_installs(app_name:app, exit_if_not_found:TRUE);

registry_init();

# only pull from registry if we can't get kb hotfix info from WMI
if(!get_kb_item("SMB/WMI/Available") || isnull(get_kb_list("WMI/Installed/Hotfix/*")))
{
  var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  var packages = get_registry_subkeys(
    handle  : hklm, 
    key     : "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");

  foreach var package (packages)
  {
    var item = pregmatch(pattern:"[^A-Za-z](KB\d{5,})([^\d]|$)", string:package);
    if (!empty_or_null(item) && !empty_or_null(item[1]))
      registry_kbs[item[1]] = TRUE;
  }
  RegCloseKey(handle:hklm);
}

close_registry(close:FALSE);

var report, latest_eff, latest_file, latest_ver, kb_str;

var systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

var latest = make_nested_array();

var cur_date = '0.0';
var last_date = '0.0';

foreach var rollup_date (rollup_dates)
{
  var patch_checks = rollup_patches[rollup_date];
  var my_os = get_kb_item("SMB/WindowsVersion");
  var my_sp = get_kb_item("SMB/CSDVersion");
  var my_arch = get_kb_item("SMB/ARCH");
  var my_os_build = get_kb_item("SMB/WindowsVersionBuild");

  if (my_sp)
  {
    my_sp = preg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else 
  {
    my_sp = 0;
  }

  foreach var patch_check (patch_checks)
  {
    var file_check, dotnet_ver, path;
    file_check = patch_check[0];
    
    # we only care about checking installed versions
    dotnet_ver = file_check[".net_version"];
    if (empty_or_null(dotnet_ver)) continue;

    var kb_inst = kb_base+"/"+rollup_date+"/"+dotnet_ver+"/";
    
    # skip over irrelevant patches
    if (file_check["os"] >!< my_os) continue;
    if (!isnull(file_check["sp"]) && my_sp != file_check["sp"]) continue;
    if (!isnull(file_check["arch"]) && my_arch != file_check["arch"]) continue;
    if (!isnull(file_check["os_build"]) && my_os_build != file_check["os_build"]) continue;
    if (!isnull(file_check["path"])) path = file_check["path"];

    var error_code = is_patched(
      file        : file_check["file"],
      version     : file_check["version"],
      path        : path,
      rollup      : rollup_date,
      dotnet_ver  : dotnet_ver,
      systemroot  : systemroot,
      winsxs      : file_check["winsxs"]);

      switch (error_code)
      {
      case HCF_OK:  # Patched
        var kb_list = patch_check[1];

        if(empty_or_null(latest[dotnet_ver]))
        {
          latest[dotnet_ver] = make_array();
          latest[dotnet_ver]['eff'] = rollup_date;
        }

        latest[dotnet_ver]['kb_str'] =  kb_list["cum"];
        if(kb_list['sec']) latest[dotnet_ver]['kb_str'] += ", " + kb_list['sec'];
        if(kb_list['pre']) latest[dotnet_ver]['kb_str'] += ", " + kb_list['pre'];

        cur_date = split(rollup_date, sep:"_", keep:FALSE);
        cur_date = cur_date[1] + "." + cur_date[0];
        last_date = split(latest[dotnet_ver]['eff'], sep:"_", keep:FALSE);
        last_date = last_date[1] + "." + last_date[0];

        if(ver_compare(ver:cur_date, fix:latest[dotnet_ver]['eff']) >=0 )
        {
          if (path =~ "winsxs") 
          {
            path = strcat(systemroot, path);
          }
          else
          {
            path = strcat(path, "\", file_check["file"]);
          }
          latest[dotnet_ver]['eff'] = rollup_date;
          latest[dotnet_ver]['file_name'] = path;
          latest[dotnet_ver]['file_ver'] = file_check["version"];
        }
        
        set_kb_item(name:kb_inst, value:1);
        set_kb_item(name:kb_inst+"file", value:latest[dotnet_ver]['file_name']);
        set_kb_item(name:kb_inst+"file_ver", value:latest[dotnet_ver]['file_ver']);

        # rollup fcheck
        fver_arr = rollup_fcheck(path:path, fix:file_check['version']);
        if (isnull(fver_arr) || isnull(fver_arr['error']))
        {
          dbg::log(src:'is_patched()', msg:'rollup_fcheck() function error');
          return FALSE;
        }

        if (!set_rollup_info(rollup:rollup_date, path:path, fver_arr:fver_arr))
          dbg::log(src:'is_patched()', msg:'set_rollup_info() function error');

        # Set dotnet rollup data for downstream Windows frictionless inventory
        if (fver_arr['error'] == HCF_OK)
        {
          replace_kb_item(name:'smb_dotnet_rollup/fa_info/' + rollup_date, value:'1;' + path + ';' + file_check['version'] + ';' + fver_arr['version']);
        }
        else
        {
          replace_kb_item(name:'smb_dotnet_rollup/fa_info/' + rollup_date, value:'0;' + path + ';' + file_check['version'] + ';' + fver_arr['version']);
        }
      case HCF_OLDER: # Not Patched
        if(empty_or_null(latest[dotnet_ver]))
          latest[dotnet_ver] = make_array();
        set_kb_item(name:kb_inst+"not_inst/cum", value:patch_check[1]["cum"]);
        if (!empty_or_null(patch_check[1]["sec"]))
        set_kb_item(name:kb_inst+"not_inst/sec", value:patch_check[1]["sec"]);
        break;

      default: # Some sort error, save the code for debugging
        set_kb_item(name:kb_inst+"error_code", value:error_code);
        break;
    }
  }
}

# cleanup connection
NetUseDel();

set_kb_item(name:"smb_check_dotnet_rollup/done", value:TRUE);

if (len(latest) == 0)
  exit(0, "No Microsoft .NET rollups were found.");

foreach var ver (keys(latest))
{
  if (empty_or_null(latest[ver]['eff']))
    set_kb_item(name:kb_base+"/"+ver+"/latest", value:"none");
  if (!empty_or_null(latest[ver]['eff']))
  {
    set_kb_item(name:kb_base+"/"+ver+"/latest", value:latest[ver]['eff']);
    
    extra['Latest effective update level'] = latest[ver]['eff'];
    extra['Associated KB'] = latest[ver]['kb_str'];
    extra['.NET Version'] = ver;

    register_install(
      app_name:app,
      path:latest[ver]['file_name'],
      version:latest[ver]['file_ver'],
      cpe:cpe,
      extra:extra
    );
  }
}

report_installs(app_name:app, port:port);
