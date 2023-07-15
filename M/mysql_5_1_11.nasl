#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17806);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/16 14:09:13");

  script_cve_id("CVE-2006-2753");
  script_bugtraq_id(18219);

  script_name(english:"MySQL < 4.1.20 / 5.0.22 / 5.1.11 SQL Injection");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to a SQL injection
attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
4.1.20 / 5.0.22 / 5.1.11 and thus reportedly allows a remote attack to
launch SQL injections by using multibyte character encodings (e.g. 
SJIS, BIG5, GBK) when mysql_real_escape is used.");
  script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/announce/364");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 4.1.20 / 5.0.22 / 5.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

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

mysql_check_version(fixed:make_list('4.1.20', '5.0.22', '5.1.11'), severity:SECURITY_HOLE);
