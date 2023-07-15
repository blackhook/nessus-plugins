#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125731);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/25");

  script_cve_id(
    "CVE-2018-3058",
    "CVE-2018-3060",
    "CVE-2018-3063",
    "CVE-2018-3064",
    "CVE-2018-3066"
  );
  script_bugtraq_id(
    104766,
    104769,
    104776,
    104786
  );

  script_name(english:"MariaDB 10.3.0 < 10.3.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mariadb.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to
10.3.9. It is, therefore, affected by multiple vulnerabilities as
referenced in the mdb-1039-rn advisory.

  - An unspecified vulnerability exists in MariaDB. An authenticated, remote attacker can exploit
  this to compromise MariaDB server, resulting in unauthorized update, insert, delete and read access
  to some of accessible data. (CVE-2018-3058, CVE-2018-3060, CVE-2018-3066)

  - A denial of service (DoS) vulnerability exists in MariaDB. An authenticated, remote attacker
  can exploit this issue, to cause the application to stop responding. (CVE-2018-3063, CVE-2018-3064)

Note that Nessus has not tested for this issue but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-1039-rn");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-14637");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-15822");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-15855");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-15953");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16131");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16515");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16596");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16664");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16675");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16713");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16809");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16830");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.3.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
   script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.3.0-MariaDB', fixed:make_list('10.3.9-MariaDB'), severity:SECURITY_WARNING);