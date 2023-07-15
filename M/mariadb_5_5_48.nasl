#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87728);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-0640",
    "CVE-2016-0641",
    "CVE-2016-0644",
    "CVE-2016-0646",
    "CVE-2016-0649",
    "CVE-2016-0650"
  );

  script_name(english:"MariaDB 5.5 < 5.5.48 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 5.5.x prior to 
5.5.48. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to impact
    integrity and availability. (CVE-2016-0640)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows an authenticated, remote attacker to
    disclose sensitive information or cause a denial of
    service condition. (CVE-2016-0641)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0644)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0646)

  - An unspecified flaw exists in the PS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0649)

  - An unspecified flaw exists in the Replication
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0650)

  - A denial of service vulnerability exists in the
    decimal2string() function due to improper handling of
    decimal precision greater than 40. An authenticated,
    remote attacker can exploit this to crash the database.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-5-5-48-and-connectorj-1-3-5-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5548-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5548-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.48-MariaDB', min:'5.5', severity:SECURITY_WARNING);
