#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129354);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id(
    "CVE-2014-4274",
    "CVE-2014-4287",
    "CVE-2014-6463",
    "CVE-2014-6478",
    "CVE-2014-6484",
    "CVE-2014-6495",
    "CVE-2014-6505",
    "CVE-2014-6520",
    "CVE-2014-6530",
    "CVE-2014-6551",
    "CVE-2015-0391"
  );
  script_bugtraq_id(
    69732,
    70455,
    70462,
    70486,
    70489,
    70496,
    70510,
    70516,
    70517,
    70532,
    72205
  );

  script_name(english:"MariaDB 5.5.0 < 5.5.39 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MariaDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 5.5.39. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-5539-release-notes advisory. These vulnerabilites relate to errors in the
following components:

  - CLIENT:MYSQLADMIN
  - CLIENT:MYSQLDUMP
  - SERVER:CHARACTER SETS
  - SERVER:DDL
  - SERVER:DML
  - SERVER:MEMORY STORAGE ENGINE
  - SERVER:MyISAM
  - SERVER:PRIVILEGES AUTHENTICATION PLUGIN API
  - SERVER:REPLICATION ROW FORMAT BINARY LOG DML
  - SERVER:SSL:yaSSL

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5539-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.39 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6530");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'5.5.0-MariaDB', fixed:make_list('5.5.39-MariaDB'), severity:SECURITY_WARNING);
