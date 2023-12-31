#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62468);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-2552");
  script_bugtraq_id(55783);
  script_xref(name:"MSFT", value:"MS12-070");
  script_xref(name:"MSKB", value:"983814");
  script_xref(name:"MSKB", value:"2716427");
  script_xref(name:"MSKB", value:"2716429");
  script_xref(name:"MSKB", value:"2716433");
  script_xref(name:"MSKB", value:"2716434");
  script_xref(name:"MSKB", value:"2716435");
  script_xref(name:"MSKB", value:"2716436");
  script_xref(name:"MSKB", value:"2716439");
  script_xref(name:"MSKB", value:"2716440");
  script_xref(name:"MSKB", value:"2716441");
  script_xref(name:"MSKB", value:"2716442");
  script_xref(name:"MSKB", value:"2754849");

  script_name(english:"MS12-070: Vulnerability in SQL Server Could Allow Elevation of Privilege (2754849) (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"A cross-site scripting vulnerability in SQL Server could allow
elevation of privilege.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Microsoft SQL Server installed. This
version of SQL Server is running SQL Server Reporting Services (SRSS),
which is affected by a cross-site scripting (XSS) vulnerability that
could allow elevation of privileges. Successful exploitation could
allow an attacker to execute arbitrary commands on the SSRS site in
the context of the targeted user. An attacker would need to entice a
user to visit a specially crafted link in order to exploit the
vulnerability.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-070
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70fa5df5");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2000, 2005,
2008, 2008 R2, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(1433, "Services/mssql");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_service(svc:"mssql", exit_on_fail:TRUE);
pcidss = get_kb_item("Settings/PCI_DSS");

ver = get_kb_item("MSSQL/" + port + "/Version");
if (!ver) audit(AUDIT_SERVICE_VER_FAIL,"MSSQL", port);

v = split(ver, sep:".", keep:FALSE);

if (
  # 2000 SP2
#  (int(v[0]) == 8 && int(v[1]) == 0 && (int(v[2]) >= 1038 && int(v[2]) < 1077)) ||
  # 2005 < SP4
  (pcidss && (int(v[0]) == 9 && int(v[1]) == 0 && int(v[2]) < 5000)) ||
  # 2005 SP4 GDR
  (int(v[0]) == 9 && int(v[1]) == 0 && (int(v[2]) >= 5000 && int(v[2]) < 5069)) ||
  # 2005 SP4 QFE
  (int(v[0]) == 9 && int(v[1]) == 0 && (int(v[2]) >= 5200 && int(v[2]) < 5324)) ||
  # 2008 < SP2
  (pcidss && (int(v[0]) == 10 && int(v[1]) == 0 && int(v[2]) < 4000)) ||
  # 2008 SP2 GDR
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 4000 && int(v[2]) < 4067)) ||
  # 2008 SP2 QFE
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 4260 && int(v[2]) < 4371)) ||
  # 2008 SP3 QFE
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5500 && int(v[2]) < 5512)) ||
  # 2008 SP3 GDR
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5750 && int(v[2]) < 5825)) ||
  # 2008 R2 < SP1
  (pcidss && (int(v[0]) == 10 && int(v[1]) == 50 && int(v[2]) < 2500)) ||
  # 2008 R2 SP1 GDR
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 2500 && int(v[2]) < 2550)) ||
  # 2008 R2 SP1 QFE
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 2750 && int(v[2]) < 2861)) ||
  # 2012 GDR
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 2100 && int(v[2]) < 2218)) ||
  # 2012 QFE
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 2300 && int(v[2]) < 2376))
)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  version = get_kb_item("MSSQL/" + port + "/Version");
  instance = get_kb_item("MSSQL/" + port + "/InstanceName");
  if(!isnull(version) || !empty_or_null(instance))
  {
    report = '';
    if(version) report += '\n  SQL Server Version   : ' + version;
    if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  }

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", ver);
