#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122484);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-7249",
    "CVE-2016-7250",
    "CVE-2016-7251",
    "CVE-2016-7252",
    "CVE-2016-7253",
    "CVE-2016-7254"
  );
  script_bugtraq_id(
    94037,
    94043,
    94050,
    94056,
    94060,
    94061
  );
  script_xref(name:"MSFT", value:"MS16-136");
  script_xref(name:"MSKB", value:"3194714");
  script_xref(name:"MSKB", value:"3194716");
  script_xref(name:"MSKB", value:"3194717");
  script_xref(name:"MSKB", value:"3194718");
  script_xref(name:"MSKB", value:"3194719");
  script_xref(name:"MSKB", value:"3194720");
  script_xref(name:"MSKB", value:"3194721");
  script_xref(name:"MSKB", value:"3194722");
  script_xref(name:"MSKB", value:"3194724");
  script_xref(name:"MSKB", value:"3194725");

  script_name(english:"MS16-136: Security Update for SQL Server (3199641) (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist
    in the SQL RDBMS Engine due to improper handling of
    pointer casting. An authenticated, remote attacker can
    exploit these to gain elevated privileges.
    (CVE-2016-7249, CVE-2016-7250, CVE-2016-7254)

  - A cross-site scripting (XSS) vulnerability exists in
    the SQL server MDS API due to improper validation of a
    request parameter on the SQL server site. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted request, to execute arbitrary code
    in the user's browser session. (CVE-2016-7251)

  - An information disclosure vulnerability exists in
    Microsoft SQL Analysis Services due to improper
    validation of the FILESTREAM path. An authenticated,
    remote attacker can exploit this to disclose sensitive
    database and file information. (CVE-2016-7252)

  - An elevation of privilege vulnerability exists in the
    Microsoft SQL Server Engine due to improper checking by
    the SQL Server Agent of ACLs on atxcore.dll. An
    authenticated, remote attacker can exploit this to gain
    elevated privileges. (CVE-2016-7253)");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-136
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fef1e99");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2012, 2014, and
2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
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
  ver_compare(minver:"11.0.5058.0", ver:ver, fix:"11.0.5388.0", strict:FALSE) < 0 ||  # 2012 SP2 GDR
  ver_compare(minver:"11.0.5500.0", ver:ver, fix:"11.0.5676.0", strict:FALSE) < 0 ||  # 2012 SP2 CU
  ver_compare(minver:"11.0.6020.0", ver:ver, fix:"11.0.6248.0", strict:FALSE) < 0 ||  # 2012 SP3 GDR
  ver_compare(minver:"11.0.6300.0", ver:ver, fix:"11.0.6567.0", strict:FALSE) < 0 ||  # 2012 SP3 CU
  ver_compare(minver:"12.0.4100.0", ver:ver, fix:"12.0.4232.0", strict:FALSE) < 0 ||  # 2014 SP1 GDR
  ver_compare(minver:"12.0.4400.0", ver:ver, fix:"12.0.4487.0", strict:FALSE) < 0 ||  # 2014 SP1 CU
  ver_compare(minver:"12.0.5000.0", ver:ver, fix:"12.0.5203.0", strict:FALSE) < 0 ||  # 2014 SP2 GDR
  ver_compare(minver:"12.0.5400.0", ver:ver, fix:"12.0.5532.0", strict:FALSE) < 0 ||  # 2014 SP2 CU
  ver_compare(minver:"13.0.1601.0", ver:ver, fix:"13.0.1722.0", strict:FALSE) < 0 ||  # 2016 GDR
  ver_compare(minver:"13.0.2100.0", ver:ver, fix:"13.0.2186.0", strict:FALSE) < 0     # 2016 CU
)
{
  report = '';
  if(!empty_or_null(version)) report += '\n  SQL Server Version   : ' + version;
  if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", version);
