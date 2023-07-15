#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73572);
  script_version("1.14");
  script_cvs_date("Date: 2019/03/27 13:17:50");

  script_cve_id(
    "CVE-2014-0001",
    "CVE-2014-0384",
    "CVE-2014-2419",
    "CVE-2014-2432",
    "CVE-2014-2438",
    "CVE-2014-4243"
  );
  script_bugtraq_id(65298, 66835, 66846, 66875, 66880, 68611);

  script_name(english:"MySQL 5.5.x < 5.5.36 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is version 5.5.x
prior to 5.5.36. It is, therefore, affected by vulnerabilities in the
following components :

  - ENFED
  - Federated
  - Partition
  - Replication
  - XML");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  # https://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77697fb1");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-36.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 5.5.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0001");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

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

mysql_check_version(fixed:'5.5.36', min:'5.5', severity:SECURITY_HOLE);
