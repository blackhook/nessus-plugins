#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125057);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-0819");
  script_xref(name:"MSKB", value:"4494352");
  script_xref(name:"MSKB", value:"4494351");
  script_xref(name:"MSFT", value:"MS19-4494352");
  script_xref(name:"MSFT", value:"MS19-4494351");
  script_xref(name:"CEA-ID", value:"CEA-2019-0326");

  script_name(english:"Security Updates for Microsoft SQL Server (May 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by an
information disclosure vulnerability that exists in  Microsoft SQL
Server Analysis Services when it improperly enforces metadata
permissions. An attacker who successfully exploited the vulnerability
could query tables or columns for which they do not have access
rights.");
  # https://support.microsoft.com/en-us/help/4494352/security-update-for-sql-server-2017-cu-14-gdr-may-14-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a9e279b");
  # https://support.microsoft.com/en-us/help/4494351/description-of-the-security-update-for-sql-server-2017-gdr-may-14-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fa2d0e0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4494352
  -KB4494351");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0819");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

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
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

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
    # 2017 GDR
    ver_compare(minver:"14.0.1000.0", ver:ver, fix:"14.0.2014.14", strict:FALSE) < 0 ||
    # 2017 CU
    ver_compare(minver:"14.0.3006.0", ver:ver, fix:"14.0.3103.1", strict:FALSE) < 0
)
{
  report = '';
  if(!empty_or_null(version)) report += '\n  SQL Server Version   : ' + version;
  if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", version);
