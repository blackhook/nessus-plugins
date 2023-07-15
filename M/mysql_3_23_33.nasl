#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17818);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/16 14:09:12");

  script_cve_id("CVE-2001-1453", "CVE-2001-1454");
  script_bugtraq_id(2262);
  script_xref(name:"CERT", value:"123384");
  script_xref(name:"CERT", value:"367320");

  script_name(english:"MySQL < 3.23.33 Multiple Buffer Overflows");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to several buffer
overflow attacks.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is affected by the
following vulnerabilities :

  - A buffer overflow in libmysqlclient.so allows a remote 
    attacker to execute arbitrary code via a long host 
    parameter. (CVE-2001-1453)

  - A buffer overflow allows a remote attacker to execute 
    arbitrary code via a long DROP DATABASE. 
    (CVE-2001-1454)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5396a2f5");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/4.1/en/news-3-23-33.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5396a2f5");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 3.23.33 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/09");
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

mysql_check_version(fixed:'3.23.33', severity:SECURITY_HOLE);
