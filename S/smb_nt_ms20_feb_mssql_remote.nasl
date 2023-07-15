#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#



# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133718);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/03");

  script_cve_id("CVE-2020-0618");
  script_xref(name:"IAVA", value:"2020-A-0074-S");
  script_xref(name:"MSKB", value:"4532095");
  script_xref(name:"MSKB", value:"4532097");
  script_xref(name:"MSKB", value:"4532098");
  script_xref(name:"MSKB", value:"4535288");
  script_xref(name:"MSKB", value:"4535706");
  script_xref(name:"MSFT", value:"MS20-4532095");
  script_xref(name:"MSFT", value:"MS20-4532097");
  script_xref(name:"MSFT", value:"MS20-4532098");
  script_xref(name:"MSFT", value:"MS20-4535288");
  script_xref(name:"MSFT", value:"MS20-4535706");
  script_xref(name:"CEA-ID", value:"CEA-2020-0018");

  script_name(english:"Security Updates for Microsoft SQL Server (Uncredentialed Check) (February 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft SQL Server Reporting Services when it
    incorrectly handles page requests. An attacker who
    successfully exploited this vulnerability could execute
    code in the context of the Report Server service
    account.  (CVE-2020-0618)");
  # https://support.microsoft.com/en-us/help/4532097/description-of-the-security-update-for-sql-server-2016-sp2-gdr-feb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff30ef1b");
  # https://support.microsoft.com/en-us/help/4535288/description-of-the-security-update-for-sql-server-2014-sp3-cu4-feb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8089305a");
  # https://support.microsoft.com/en-us/help/4532095/description-of-the-security-update-for-sql-server-2014-sp3-gdr-feb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?899d9f68");
  # https://support.microsoft.com/en-us/help/4532098/security-update-for-sql-server-2012-sp4-gdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c9e8cfc");
  # https://support.microsoft.com/en-us/help/4535706/description-of-the-security-update-for-sql-server-2016-sp2-cu11-februa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?226a31d0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4532095
  -KB4532097
  -KB4532098
  -KB4535288
  -KB4535706");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0618");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SQL Server Reporting Services (SSRS) ViewState Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

port = get_service(svc:'mssql', exit_on_fail:TRUE);
instance = get_kb_item('MSSQL/' + port + '/InstanceName');
version = get_kb_item_or_exit('MSSQL/' + port + '/Version');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = pregmatch(pattern:"^([0-9.]+)([^0-9]|$)", string:version);
if (!isnull(ver) && !isnull(ver[1])) ver = ver[1];

if (
    # 2012 SP4 GDR
    # KB4532098
    ver_compare(minver:'11.0.5200.0', ver:ver, fix:'11.0.7493.0', strict:FALSE) < 0 ||
    # 2014 SP3 GDR
    # KB 4532095
    ver_compare(minver:'12.0.6000.0', ver:ver, fix:'12.0.6118.0', strict:FALSE) < 0 ||
    # 2014 SP3 CU4
    # KB 4535288
    ver_compare(minver:'12.0.6200.0', ver:ver, fix:'12.0.6372.0', strict:FALSE) < 0 ||
    # 2016 SP2 GDR
    # KB 4532097
    ver_compare(minver:'13.0.5000.0', ver:ver, fix:'13.0.5102.0', strict:FALSE) < 0 ||
    # 2016 SP2 CU11
    # KB 4535706
    ver_compare(minver:'13.0.5149.0', ver:ver, fix:'13.0.5622.0', strict:FALSE) < 0
  )
{
  report = '';
  if (!empty_or_null(version))  report += '\n  SQL Server Version   : ' + version;
  if (!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'MSSQL', version);

