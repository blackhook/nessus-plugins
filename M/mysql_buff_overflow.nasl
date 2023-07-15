#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14319);
  script_version("1.24");
  script_cvs_date("Date: 2018/07/16 14:09:13");
 
  script_cve_id("CVE-2004-0836");
  script_bugtraq_id(10981);
  
  script_name(english:"MySQL < 4.0.21 mysql_real_connect() Function Remote Overflow");
  script_summary(english:"Checks for the remote MySQL version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MySQL that is older than 
4.0.21.

MySQL is a database that runs on both Linux/BSD and Windows platforms.
This version is vulnerable to a length overflow within it's 
mysql_real_connect() function.  The overflow is due to an error in the
processing of a return Domain (DNS) record.  An attacker, exploiting
this flaw, would need to control a DNS server, which would be queried
by the MySQL server.  A successful attack would give the attacker
the ability to execute arbitrary code on the remote machine.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=4017");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110140517515735&w=2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.0.21 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/20");
 
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Databases");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'4.0.21', severity:SECURITY_HOLE);
