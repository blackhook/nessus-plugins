#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170144);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/20");

  script_cve_id(
    "CVE-2022-32221",
    "CVE-2023-21836",
    "CVE-2023-21863",
    "CVE-2023-21867",
    "CVE-2023-21868",
    "CVE-2023-21869",
    "CVE-2023-21870",
    "CVE-2023-21871",
    "CVE-2023-21873",
    "CVE-2023-21875",
    "CVE-2023-21876",
    "CVE-2023-21877",
    "CVE-2023-21878",
    "CVE-2023-21879",
    "CVE-2023-21880",
    "CVE-2023-21881",
    "CVE-2023-21882",
    "CVE-2023-21883",
    "CVE-2023-21887"
  );
  script_xref(name:"IAVA", value:"2023-A-0043");

  script_name(english:"Oracle MySQL Server (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
October 2022 CPU advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (cURL)).
    Supported versions that are affected are 5.7.40 and prior and 8.0.31 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in takeover of MySQL Server.
    (CVE-2022-32221)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of MySQL Server (CVE-2023-21868)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that
    are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. (CVE-2023-21869).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(fixed:'8.0.32', min:'8.0', severity:SECURITY_HOLE);
