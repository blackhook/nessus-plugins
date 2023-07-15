#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17814);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2008-0226", "CVE-2008-0227");
  script_bugtraq_id(27140);	# 31681 is retired

  script_name(english:"yaSSL 1.7.5 Buffer Overflow");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote database server.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host reportedly allows a
remote user to execute arbitrary code by exploiting a buffer overflow
in yaSSL 1.7.5 or earlier.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=33814");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/485810/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.0.54a, 5.1.23, 6.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL SSL Hello Message Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/22");
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

mysql_check_version(fixed:make_list('5.0.55', '5.1.23', '6.0.4'), severity:SECURITY_HOLE);
