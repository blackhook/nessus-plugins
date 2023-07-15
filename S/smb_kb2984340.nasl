#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77161);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-1820", "CVE-2014-4061");
  script_bugtraq_id(69071, 69088);
  script_xref(name:"MSFT", value:"MS14-044");
  script_xref(name:"MSKB", value:"2984340");

  script_name(english:"MS14-044: Vulnerability in SQL Server Could Allow Elevation of Privilege (2984340) (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"A cross-site scripting vulnerability in SQL Server could allow an
elevation of privilege.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Microsoft SQL Server installed. This
version of SQL Server is potentially affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    SQL Master Data Services. (CVE-2014-1820)

  - A denial of service vulnerability exists in SQL Server.
    (CVE-2014-4061)");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7712db7a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2008, 2008 R2,
2012, and 2014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  # 2008 < SP3
  (pcidss && (int(v[0]) == 10 && int(v[1]) == 0 && int(v[2]) < 5500)) ||
  # 2008 SP3 GDR
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5500 && int(v[2]) < 5520)) ||
  # 2008 SP3 QFE
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5750 && int(v[2]) < 5869)) ||
  # 2008 R2 < SP2
  (pcidss && (int(v[0]) == 10 && int(v[1]) == 50 && int(v[2]) < 4000)) ||
  # 2008 R2 SP2 GDR
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 4000 && int(v[2]) < 4033)) ||
  # 2008 R2 SP2 QFE
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 4251 && int(v[2]) < 4321)) ||
  # 2012 < SP1
  (pcidss && (int(v[0]) == 11 && int(v[1]) == 0 && int(v[2]) < 3000)) ||
  # 2012 GDR
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 3000 && int(v[2]) < 3153)) ||
  # 2012 QFE
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 3300 && int(v[2]) < 3460)) ||
  # 2014 GDR
  (int(v[0]) == 12 && int(v[1]) == 0 && (int(v[2]) >= 2000 && int(v[2]) < 2254)) ||
  # 2014 QFE
  (int(v[0]) == 12 && int(v[1]) == 0 && (int(v[2]) >= 2300 && int(v[2]) < 2381))
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
