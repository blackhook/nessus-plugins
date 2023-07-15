#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34311);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2008-0085",
    "CVE-2008-0086",
    "CVE-2008-0106",
    "CVE-2008-0107"
  );
  script_bugtraq_id(
    30082,
    30083,
    30118,
    30119
  );
  script_xref(name:"MSFT", value:"MS08-040");
  script_xref(name:"MSKB", value:"941203");

  script_name(english:"MS08-040: Microsoft SQL Server Multiple Privilege Escalation (941203) (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft SQL Server, Desktop
Engine, or Internal Database that is affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists due to
    improper initialization of memory pages when
    reallocating memory. An unauthenticated, remote attacker
    can exploit this to obtain database contents, resulting
    in the disclosure of sensitive information.
    (CVE-2008-0085)

  - A remote code execution vulnerability exists due to a
    buffer overflow condition in the convert() function. An
    authenticated, remote attacker can exploit this, via a
    crafted SQL expression, to execute arbitrary code.
    (CVE-2008-0086)

  - A remote code execution vulnerability exists due to an
    unspecified buffer overflow condition. An authenticated,
    remote attacker can exploit this, via a crafted insert
    statement, to execute arbitrary code. (CVE-2008-0086)

  - A remote code execution vulnerability exists due to an
    integer underflow condition. An authenticated, remote
    attacker can exploit this, via an SMB or WebDAV pathname
    for an on-disk file with a crafted record size value, to
    cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code. (CVE-2008-0107)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-040");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 7, 2000, and
2005.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(1433, "Services/mssql");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "MSSQL Server";

port = get_service(svc:"mssql", default:1433, exit_on_fail:TRUE);
version = get_kb_item_or_exit("MSSQL/"+port+"/Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
fix = '';

if (version =~ "^\d+(\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if ( version =~ "^7\.0\." )
  fix = "7.0.1152";
if ( version =~ "^8\.0\." )
  fix = "8.0.2050";
if ( version =~ "^9\.0\." )
  fix = "9.0.3068";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';

  instance = get_kb_item("MSSQL/" + port + "/InstanceName");
  if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
