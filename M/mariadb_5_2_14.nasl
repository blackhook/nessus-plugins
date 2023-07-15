#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64933);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2012-0572",
    "CVE-2012-0574",
    "CVE-2012-1702",
    "CVE-2012-1705",
    "CVE-2012-5611",
    "CVE-2012-5612",
    "CVE-2012-5615",
    "CVE-2012-5627",
    "CVE-2013-0375",
    "CVE-2013-0383",
    "CVE-2013-0384",
    "CVE-2013-0385",
    "CVE-2013-0389",
    "CVE-2013-1531"
  );
  script_bugtraq_id(
    56766,
    56768,
    56769,
    56837,
    57385,
    57388,
    57391,
    57405,
    57410,
    57412,
    57414,
    57416,
    57417
  );
  script_xref(name:"EDB-ID", value:"23075");
  script_xref(name:"EDB-ID", value:"23076");

  script_name(english:"MariaDB 5.2 < 5.2.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.2 running on the remote host is prior to
5.2.14. It is, therefore, potentially affected by vulnerabilities in
the following components :

  - Information Schema
  - InnoDB
  - Server
  - Server Locking
  - Server Optimizer
  - Server Privileges
  - Server Replication");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5214-release-notes/");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-67.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.2.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0385");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-0375");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.2.14-MariaDB', min:'5.2', severity:SECURITY_WARNING);
