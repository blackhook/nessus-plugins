#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104437);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-3308",
    "CVE-2017-3309",
    "CVE-2017-3453",
    "CVE-2017-3456",
    "CVE-2017-3464"
  );
  script_bugtraq_id(
    97725,
    97742,
    97776,
    97818,
    97831
  );

  script_name(english:"MariaDB 10.0.x < 10.0.31 / 10.1.x < 10.1.23 / 10.2.x < 10.2.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is prior to
10.0.x prior to 10.0.31, 10.1.x prior to 10.1.23, or 10.2.x
prior to 10.2.7. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10031-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10123-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-1027-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.31 / 10.1.23 / 10.2.7 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3464");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:make_list('10.0.31-MariaDB', '10.1.23-MariaDB', '10.2.7-MariaDB'), severity:SECURITY_WARNING);
