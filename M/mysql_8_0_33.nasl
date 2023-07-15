#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174555);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-43551",
    "CVE-2023-0215",
    "CVE-2023-21911",
    "CVE-2023-21919",
    "CVE-2023-21920",
    "CVE-2023-21929",
    "CVE-2023-21933",
    "CVE-2023-21935",
    "CVE-2023-21940",
    "CVE-2023-21945",
    "CVE-2023-21946",
    "CVE-2023-21947",
    "CVE-2023-21953",
    "CVE-2023-21955",
    "CVE-2023-21962",
    "CVE-2023-21966",
    "CVE-2023-21972",
    "CVE-2023-21976",
    "CVE-2023-21977",
    "CVE-2023-21980",
    "CVE-2023-21982"
  );
  script_xref(name:"IAVA", value:"2023-A-0212");

  script_name(english:"Oracle MySQL Server (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
April 2023 CPU advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (OpenSSL)).
    Supported versions that are affected are 5.7.41 and prior and 8.0.32 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2023-0215)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (cURL)). Supported
    versions that are affected are 5.7.41 and prior and 8.0.32 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all MySQL Server accessible data. (CVE-2022-43551)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 5.7.41 and prior and 8.0.30 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2023-21912)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43551");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

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

mysql_check_version(fixed:'8.0.33', min:'8.0', severity:SECURITY_HOLE);
