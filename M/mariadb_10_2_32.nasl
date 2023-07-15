#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138101);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2020-2752",
    "CVE-2020-2760",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-13249"
  );

  script_name(english:"MariaDB 10.2.0 < 10.2.32 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.2.32. It is, therefore, affected by multiple
vulnerabilities as referenced in the mdb-10232-rn advisory.

  - Vulnerability in the MySQL Client product of Oracle
    MySQL (component: C API). Supported versions that are
    affected are 5.6.47 and prior, 5.7.27 and prior and
    8.0.17 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. CVSS
    3.0 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2020-2752)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.29 and prior and 8.0.19 and prior.
    Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update,
    insert or delete access to some of MySQL Server
    accessible data. CVSS 3.0 Base Score 5.5 (Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).
    (CVE-2020-2760)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.47 and prior, 5.7.29
    and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2020-2812)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: InnoDB). Supported versions that are
    affected are 5.6.47 and prior, 5.7.28 and prior and
    8.0.18 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2020-2814)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10232-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.2.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13249");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Service/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.2.0-MariaDB', fixed:make_list('10.2.32-MariaDB'), severity:SECURITY_WARNING);