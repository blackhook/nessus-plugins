#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62637);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173");
  script_bugtraq_id(56018, 56028, 56041);
  
  script_name(english:"MySQL 5.1 < 5.1.64 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote database server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.64 and is, therefore, affected by vulnerabilities in the following
components :

  - InnoDB
  - InnoDB Plugin
  - Server Full Text Search"
  );
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-64.html");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87547c81");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.1.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.1.64', min:'5.1', severity:SECURITY_WARNING);
