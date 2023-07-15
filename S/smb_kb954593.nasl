#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106298);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-5348",
    "CVE-2008-3012",
    "CVE-2008-3013",
    "CVE-2008-3014",
    "CVE-2008-3015"
  );
  script_bugtraq_id(
    31018,
    31019,
    31020,
    31021,
    31022
  );
  script_xref(name:"MSFT", value:"MS08-052");
  script_xref(name:"MSKB", value:"938464");
  script_xref(name:"MSKB", value:"954326");
  script_xref(name:"MSKB", value:"954478");
  script_xref(name:"MSKB", value:"954479");
  script_xref(name:"MSKB", value:"954606");

  script_name(english:"MS08-052: Vulnerabilities in GDI+ Could Allow Remote Code Execution (954593) (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple arbitrary execution flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that has multiple
buffer overflow vulnerabilities when viewing VML, EMF, GIF, WMF and
BMP files that could allow an attacker to execute arbitrary code on
the remote host.

To exploit these flaws, an attacker would need to send a malformed
image file to a user on the remote host and wait for the user to
open it using an affected Microsoft application.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-052");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2000 and
2005.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(1433, "Services/mssql");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"mssql", exit_on_fail:TRUE);

ver = get_kb_item("MSSQL/" + port + "/Version");
if (!ver) audit(AUDIT_SERVICE_VER_FAIL,"MSSQL", port);

v = split(ver, sep:".", keep:FALSE);
for (i=0; i < max_index(v); i++)
  v[i] = int(v[i]);

if (report_paranoia < 2) audit(AUDIT_PARANOID);
pcidss = get_kb_item("Settings/PCI_DSS");

vuln = 0;

if (pcidss && (v[0] == 8 && v[1] == 0 && v[2] < 534)) # 2000 < SP2
{
  vuln++;
  fix = "8.0.1062";
}
else if (v[0] == 8 && v[1] == 0 && (v[2] >= 1038 && v[2] < 1062))  # 2000 SP2
{
  vuln++;
  fix = "8.0.1062";
}
else if (pcidss && (v[0] == 9 && v[1] == 0 && v[2] < 3042)) # 2005 < SP2 
{
  vuln++;
  fix = "9.0.3072";
}
else if (v[0] == 9 && v[1] == 0 && (v[2] >= 3000 && v[2] < 3072)) # 2005 SP2 GDR
{
  vuln++;
  fix = "9.0.3072";
}
else if (v[0] == 9 && v[1] == 0 && (v[2] >= 3200 && v[2] < 3281))
{
  vuln++;
  fix = "9.0.3281";
}
if(vuln > 0)
{
  report = '\n  Installed Version : ' + ver;
  report +='\n  Fixed Version     : ' + fix +'\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else 
  audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", ver);
