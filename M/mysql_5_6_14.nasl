#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71975);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id(
    "CVE-2013-5882",
    "CVE-2013-5891",
    "CVE-2013-5894",
    "CVE-2014-0386",
    "CVE-2014-0393",
    "CVE-2014-0402",
    "CVE-2014-0427",
    "CVE-2014-0430",
    "CVE-2014-0433"
  );
  script_bugtraq_id(
    64854,
    64868,
    64873,
    64877,
    64891,
    64893,
    64895,
    64904,
    64908
  );

  script_name(english:"MySQL 5.6.x < 5.6.14 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is 5.6.x older than
5.6.14.  As such, it is reportedly affected by vulnerabilities in the
following components :

  - FTS
  - InnoDB
  - Locking
  - Optimizer
  - Partition
  - Performance Schema
  - Stored Procedure
  - Thread Pooling");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-14.html");
  # https://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ac50e41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 5.6.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

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

mysql_check_version(fixed:'5.6.14', min:'5.6', severity:SECURITY_NOTE);
