#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17813);
  script_version("1.9");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2007-6303", "CVE-2007-6304");
  script_bugtraq_id(26832);

  script_name(english:"MySQL < 5.0.51a / 5.1.23 / 6.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
5.0.51a / 5.1.23 / 6.0.4 and thus reportedly affected by the following
two vulnerabilities :

  - An attacker may be able to cause the federated handler
    and daemon to crash when the federated engine issues a
    SHOW TABLE STATUS LIKE query by having a malicious
    server return a response with less than 14 columns.
    (MySQL bug #29801 / CVE-2007-6304)

  - It fails to update the DEFINER value of a view when that
    is altered, which could allow an authenticated user to
    gain additional access through the ALTER VIEW. (MySQL 
    bug #29908 / CVE-2007-6303)");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=29801");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=29908");
  script_set_attribute(attribute:"see_also", value:"https://lists.mysql.com/announce/502");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-23.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.51a / 5.1.23 / 6.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/14");
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

mysql_check_version(fixed:make_list('5.0.51a', '5.1.23', '6.0.4'), severity:SECURITY_WARNING);
