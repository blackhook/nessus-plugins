#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 
 script_id(15477);  
 script_version("1.25");
 script_cvs_date("Date: 2018/11/15 20:50:21");

 script_cve_id("CVE-2004-0957", "CVE-2004-0956");
 script_bugtraq_id(11435, 11432);
 script_xref(name:"DSA", value:"707");
 script_xref(name:"GLSA", value:"200410-22");
 script_xref(name:"RHSA", value:"2004:611");
 
 script_name(english:"MySQL < 4.0.21 Multiple Vulnerabilities");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"You are running a version of MySQL which is older than version 4.0.21.
Such versions are potentially affected by two flaws :

  - There is an unauthorized database GRANT privilege 
    vulnerability, which may allow an attacker to misuse the
    GRANT privilege it has been given and to use it against
    other databases. (CVE-2004-0957)

  - A denial of service vulnerability may be triggered by 
    the misuse of the FULLTEXT search functionality.
    (CVE-2004-0956)");
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=3870");
 script_set_attribute(attribute:"see_also", value:"https://www.suse.com/support/security/");
 script_set_attribute(attribute:"see_also", value:"http://www.ubuntulinux.org/usn/usn-109-1");
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=3933");
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.0.21 or later, as this reportedly fixes the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/17");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/29");

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

#
# The script code starts here
#

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
  version = mysql_get_version();

  if (
    strlen(version) &&
    version =~ "^([0-3]\.|4\.0\.([0-9]|1[0-9]|20)([^0-9]|$))"
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

