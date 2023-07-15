#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122486);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-8273");
  script_bugtraq_id(104967);
  script_xref(name:"MSFT", value:"MS18-4458842");
  script_xref(name:"MSFT", value:"MS18-4293808");
  script_xref(name:"MSFT", value:"MS18-4293802");
  script_xref(name:"MSFT", value:"MS18-4458621");
  script_xref(name:"MSFT", value:"MS18-4293803");
  script_xref(name:"MSFT", value:"MS18-4293805");
  script_xref(name:"MSKB", value:"4458842");
  script_xref(name:"MSKB", value:"4293808");
  script_xref(name:"MSKB", value:"4293802");
  script_xref(name:"MSKB", value:"4458621");
  script_xref(name:"MSKB", value:"4293803");
  script_xref(name:"MSKB", value:"4293805");

  script_name(english:"Security Updates for Microsoft SQL Server 2016 and 2017 x64 (August 2018) (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by buffer overflow vulnerability that could allow
remote code execution on an affected system.
An attacker who successfully exploited the vulnerability could execute code
in the context of the SQL Server Database Engine service account.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02637930");
  # https://support.microsoft.com/en-us/help/4458842/description-of-the-security-update-for-the-remote-code-execution-vulne
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5296772");
  # https://support.microsoft.com/en-us/help/4293808/security-update-for-remote-code-execution-vulnerability-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ded4707c");
  # https://support.microsoft.com/en-us/help/4293802/description-of-the-security-update-for-the-remote-code-execution-vulne
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc2f6328");
  # https://support.microsoft.com/en-us/help/4458621/description-of-the-security-update-for-the-remote-code-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ab5e14c");
  # https://support.microsoft.com/en-us/help/4293803/description-of-the-security-update-for-the-remote-code-execution-vulne
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c6a7711");
  # https://support.microsoft.com/en-us/help/4293805/security-update-for-remote-code-execution-vulnerability-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82d9f22e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for x64 versions of SQL Server 2016 and 2017.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8273");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/13");
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
     # 2016 GDR SP1
    ver_compare(minver:"13.0.4001.0", ver:ver, fix:"13.0.4224.0", strict:FALSE) < 0 ||
    # 2016 CU SP1
    ver_compare(minver:"13.0.4411.0", ver:ver, fix:"13.0.4522.0", strict:FALSE) < 0 ||
    # 2016 GDR SP2
    ver_compare(minver:"13.0.5026.0", ver:ver, fix:"13.0.5081.0", strict:FALSE) < 0 ||
    # 2016 CU SP2
    ver_compare(minver:"13.0.5149.0", ver:ver, fix:"13.0.5201.0", strict:FALSE) < 0 ||
    # 2017 GDR
    ver_compare(minver:"14.0.1000.0", ver:ver, fix:"14.0.2002.0", strict:FALSE) < 0 ||
    # 2017 CU
    ver_compare(minver:"14.0.3006.0", ver:ver, fix:"14.0.3035.0", strict:FALSE) < 0 
)
{
  report = '';
  if(!empty_or_null(version)) report += '\n  SQL Server Version   : ' + version;
  if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", version);
