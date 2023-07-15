#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17838);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2005-0004");
  script_bugtraq_id(12277);

  script_name(english:"MySQL < 3.23.50 / 4.0.24 / 4.1.6 / 5.0.3 Insecure Temporary File Creation");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files could be read or overwritten via the remote database
server.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
3.23.50, 4.0.24, 4.1.6 or 5.0.3.  As such, the mysqlaccess script
included with it reportedly could be used to read or overwrite
arbitrary files via a symlink attack.");
  script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/internals/20600");
  script_set_attribute(attribute:"see_also", value:"https://lists.mysql.com/announce/269");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 3.23.50 / 4.0.24 / 4.1.6 / 5.0.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

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

mysql_check_version(fixed:make_list('3.23.50', '4.0.24', '4.1.6', '5.0.3'), severity:SECURITY_WARNING);
