#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34727);
  script_version("1.15");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2008-2079", "CVE-2008-4098");
  script_bugtraq_id(29106);

  script_name(english:"MySQL Enterprise Server 5.0 < 5.0.70 Privilege Bypass");
  script_summary(english:"Checks version of MySQL Enterprise Server 5.0");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to a privilege bypass
attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Server 5.0 installed on the remote
host is earlier than 5.0.70.  In such versions, it is possible for a
local user to circumvent privileges through the creation of MyISAM
tables employing the 'DATA DIRECTORY' and 'INDEX DIRECTORY' options to
overwrite existing table files in the application's data directory. 

Note that this issue was supposed to have been addressed in version
5.0.60, but the fix was incomplete.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=32167");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-70.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2008/09/09/20");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2008/09/16/3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise version 5.0.70 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  variant = mysql_get_variant();
  version = mysql_get_version();

  if (
    "Enterprise " >< variant && 
    strlen(version) && 
    version =~ "^5\.0\.([0-9]|[1-6][0-9])($|[^0-9])"
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\nThe remote MySQL '+variant+'\'s version is :\n'+
        '  '+version+'\n';
      datadir = get_kb_item('mysql/' + port + '/datadir');
      if (!empty_or_null(datadir))
      {
        report += '  Data Dir          : ' + datadir + '\n';
      }
      databases = get_kb_item('mysql/' + port + '/databases');
      if (!empty_or_null(databases))
      { 
        report += '  Databases         :\n' + databases;
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
mysql_close();
