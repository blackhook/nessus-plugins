#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122485);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-8516");
  script_bugtraq_id(100041);
  script_xref(name:"MSKB", value:"4036996");
  script_xref(name:"MSKB", value:"4032542");
  script_xref(name:"MSKB", value:"4019095");
  script_xref(name:"MSKB", value:"4019093");
  script_xref(name:"MSKB", value:"4019092");
  script_xref(name:"MSKB", value:"4019091");
  script_xref(name:"MSKB", value:"4019090");
  script_xref(name:"MSKB", value:"4019089");
  script_xref(name:"MSKB", value:"4019088");
  script_xref(name:"MSKB", value:"4019086");
  script_xref(name:"MSFT", value:"MS17-4036996");
  script_xref(name:"MSFT", value:"MS17-4032542");
  script_xref(name:"MSFT", value:"MS17-4019095");
  script_xref(name:"MSFT", value:"MS17-4019093");
  script_xref(name:"MSFT", value:"MS17-4019092");
  script_xref(name:"MSFT", value:"MS17-4019091");
  script_xref(name:"MSFT", value:"MS17-4019090");
  script_xref(name:"MSFT", value:"MS17-4019089");
  script_xref(name:"MSFT", value:"MS17-4019088");
  script_xref(name:"MSFT", value:"MS17-4019086");

  script_name(english:"KB4036996: Security Update for SQL Server (August 2017) (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by an information disclosure vulnerability in
Microsoft SQL Server Analysis Services when it improperly enforces
permissions. An attacker could exploit the vulnerability if the
attacker's credentials allow access to an affected SQL server
database. An attacker who successfully exploited the vulnerability
could gain additional database and file information.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4036996");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4032542");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019095");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019093");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019092");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019091");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019090");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019089");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019088");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019086");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2012, 2014, and
2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
instance = get_kb_item("MSSQL/" + port + "/InstanceName");
version = get_kb_item_or_exit("MSSQL/" + port + "/Version");

ver = pregmatch(pattern:"^([0-9.]+)([^0-9]|$)", string:version);
if(!isnull(ver) && !isnull(ver[1])) ver = ver[1];

if (
    # 2012 GDR SP3
    ver_compare(minver:"11.0.6020.0", ver:ver, fix:"11.0.6251.0", strict:FALSE) < 0 ||
    # 2012 CU SP3 
    ver_compare(minver:"11.0.6518.0", ver:ver, fix:"11.0.6607.0", strict:FALSE) < 0 ||
    # 2014 GDR SP1 
    ver_compare(minver:"12.0.4100.0", ver:ver, fix:"12.0.4237.0", strict:FALSE) < 0 ||
    # 2014 CU SP1 
    ver_compare(minver:"12.0.4416.0", ver:ver, fix:"12.0.4522.0", strict:FALSE) < 0 ||
    # 2014 GDR SP2 
    ver_compare(minver:"12.0.5000.0", ver:ver, fix:"12.0.5207.0", strict:FALSE) < 0 ||
    # 2014 CU SP2 
    ver_compare(minver:"12.0.5511.0", ver:ver, fix:"12.0.5553.0", strict:FALSE) < 0 ||
    # 2016 RTM CU 
    ver_compare(minver:"13.0.2149.0", ver:ver, fix:"13.0.2210.0", strict:FALSE) < 0 ||
    # 2016 GDR 
    ver_compare(minver:"13.0.1601.0", ver:ver, fix:"13.0.1742.0", strict:FALSE) < 0 ||
    # 2016 GDR SP1 
    ver_compare(minver:"13.0.4000.0", ver:ver, fix:"13.0.4206.0", strict:FALSE) < 0 ||
    # 2016 CU SP1
    ver_compare(minver:"13.0.4411.0", ver:ver, fix:"13.0.4446.0", strict:FALSE) < 0
)
{
  report = '';
  if(!empty_or_null(version)) report += '\n  SQL Server Version   : ' + version;
  if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", version);
