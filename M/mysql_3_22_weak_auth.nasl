#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17816);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2000-0981");
  script_bugtraq_id(1826);

  script_name(english:"MySQL 3.x Password Disclosure");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to information
disclosure.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host reportedly uses a
weak algorithm for authentication. 

A remote attacker who can monitor network traffic could retrieve
passwords by breaking the used cryptographic algorithms.");
  # https://www.secureauth.com/labs/advisories/vulnerability-report-for-mysql-authentication
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c288d952");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?609fdc42");
  script_set_attribute(attribute:"solution", value:
"No fix for MySQL 3.x has been published.

Upgrade to MySQL version 5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/12/27");
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

mysql_check_version(fixed:'4.0', severity:SECURITY_HOLE);
