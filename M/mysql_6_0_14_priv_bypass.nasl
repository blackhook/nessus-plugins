#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17812);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2008-4097");
  script_bugtraq_id(29106);

  script_name(english:"MySQL < 5.0.88 / 5.1.42 / 5.5.0 / 6.0.14 MyISAM CREATE TABLE Privilege Check Bypass");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server allows a local user to circumvent
privileges.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
5.0.88 / 5.1.42 / 5.5.0 / 6.0.14 and thus reportedly allows a local
user to circumvent privileges through creation of MyISAM tables using
the 'DATA DIRECTORY' and 'INDEX DIRECTORY' options to overwrite
existing table files in the application's data directory.  This is the
same flaw as CVE-2008-2079, which was not completely fixed.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=32167?");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.0.88 / 5.1.42 / 5.5.0 / 6.0.14 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/07");
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

mysql_check_version(fixed:make_list('5.0.88', '5.1.42', '5.5.0', '6.0.14'), severity:SECURITY_WARNING);
