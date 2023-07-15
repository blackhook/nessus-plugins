#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63617);
  script_version("1.10");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2012-0572",
    "CVE-2012-0574",
    "CVE-2012-1702",
    "CVE-2012-1705",
    "CVE-2012-5611",
    "CVE-2013-0375",
    "CVE-2013-0383",
    "CVE-2013-0384",
    "CVE-2013-0385",
    "CVE-2013-0389"
  );
  script_bugtraq_id(
    56769,
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

  script_name(english:"MySQL 5.1 < 5.1.67 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.67 and is, therefore, affected by vulnerabilities in the following
components :

  - Information Schema
  - InnoDB
  - Server
  - Server Locking
  - Server Optimizer
  - Server Privileges
  - Server Replication");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-67.html");
  # https://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ff06601");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.1.67 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0385");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.1.67', min:'5.1', severity:SECURITY_WARNING);
