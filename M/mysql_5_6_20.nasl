#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77670);
  script_version("1.17");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2012-5615",
    "CVE-2014-0224",
    "CVE-2014-4274",
    "CVE-2014-4287",
    "CVE-2014-6463",
    "CVE-2014-6474",
    "CVE-2014-6478",
    "CVE-2014-6484",
    "CVE-2014-6489",
    "CVE-2014-6495",
    "CVE-2014-6505",
    "CVE-2014-6530",
    "CVE-2014-6551",
    "CVE-2014-6564",
    "CVE-2015-0391"
  );
  script_bugtraq_id(
    56766,
    67899,
    69732,
    70448,
    70455,
    70462,
    70486,
    70489,
    70496,
    70511,
    70516,
    70517,
    70525,
    70532,
    72205
  );

  script_name(english:"MySQL 5.6.x < 5.6.20 Multiple Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is version 5.6.x
prior to 5.6.20. It is, therefore, affected by errors in the following
components :

  - CLIENT:MYSQLADMIN
  - CLIENT:MYSQLDUMP
  - SERVER:CHARACTER SETS
  - SERVER:DML
  - SERVER:MEMORY STORAGE ENGINE
  - SERVER:MyISAM
  - SERVER:PRIVILEGES AUTHENTICATION PLUGIN API
  - SERVER:REPLICATION ROW FORMAT BINARY LOG DML
  - SERVER:SSL:OpenSSL
  - SERVER:SSL:yaSSL");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5134a40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.20 or later as referenced in the October
2014 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6530");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");
mysql_check_version(fixed:'5.6.20', min:'5.6.0', severity:SECURITY_WARNING);
