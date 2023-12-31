#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35766);
  script_version("1.16");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2009-0819");
  script_bugtraq_id(33972);
  script_xref(name:"Secunia", value:"34115");

  script_name(english:"MySQL 5.1 < 5.1.32 XPath Expression DoS");
  script_summary(english:"Checks version of MySQL 5.1 Server");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server is affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.32 and is, therefore, affected by a denial of service vulnerability.
Specifically, an authenticated user can cause an assertion failure
leading to a server crash by calling 'ExtractValue()' or 'UpdateXML()'
using an XPath expression employing a scalar expression as a
'FilterExpr'."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://bugs.mysql.com/bug.php?id=42495"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-32.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to MySQL Community Server version 5.1.32 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  variant = mysql_get_variant();
  version = mysql_get_version();

  if (
    "Community" >< variant && 
    strlen(version) &&
    version =~ "^5\.1\.([0-9]|[12][0-9]|3[0-1])($|[^0-9])"
  )
  {
    if (report_verbosity > 0)
    {
      report = '\nThe remote MySQL server\'s version is :\n\n  '+version+'\n';
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
