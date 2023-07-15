#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105078);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:21");


  script_name(english:"MariaDB 10.3.x < 10.3.1  Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of
service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is prior to
10.3.1. It is, therefore, affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-1031-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB',min:'10.3.0-MariaDB', fixed:make_list('10.3.1-MariaDB'), severity:SECURITY_WARNING);
