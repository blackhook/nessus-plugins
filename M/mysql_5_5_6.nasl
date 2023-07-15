#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17836);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836" , "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839");
  script_bugtraq_id(43676);

  script_name(english:"MySQL < 5.5.6 Multiple Denial of Service");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to multiple denial of
service attacks.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
5.5.6.  As such, it reportedly is prone to multiple denial of service
attacks :

  - The improper handling of type errors during argument 
    evaluation in extreme-value functions, e.g., 'LEAST()'
    or 'GREATEST()' causes server crashes. (CVE-2010-3833)

  - Remote authenticated attackers could crash the server.
    (CVE-2010-3834 & CVE-2010-3836)

  - The use of 'GROUP_CONCAT()' and 'WITH ROLLUP' caused
    server crashes. (CVE-2010-3837)

  - The use of an intermediate temporary table and queries
    containing calls to 'GREATEST()' or 'LEAST()', having 
    a list of both numeric and 'LONGBLOB' arguments, caused
    server crashes. (CVE-2010-3838)

  - The use of nested joins in prepared statements or
    stored procedures could result in infinite loops. 
    (CVE-2010-3839)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640751");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=55826");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=54476");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=54461");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=53544");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-6.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/10");
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

mysql_check_version(fixed:'5.5.6', severity:SECURITY_WARNING, min:'5.5');
