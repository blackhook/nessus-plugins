#%NASL_MIN_LEVEL 70300
#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (1/23/09)
# - changed family (9/5/09)
# - Updated to use compat.inc (11/20/2009)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11378);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0150");
  script_bugtraq_id(7052);

  script_name(english:"MySQL datadir/my.cnf Modification Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is prone to a privilege escalation attack.");
  script_set_attribute(attribute:"description", value:
"The remote version of MySQL is older than 3.23.56.  Such versions are
affected by an issue that may allow the mysqld service to start with
elevated privileges.  An attacker can exploit this vulnerability by
creating a 'DATADIR/my.cnf' that includes the line 'user=root' under
the '[mysqld]' option section.  When the mysqld service is executed,
it will run as the root user instead of the default user.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Mar/133");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Mar/144");
  script_set_attribute(attribute:"solution", value:
"Upgrade to at least version 3.23.56.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2003-2022 StrongHoldNet");

  script_dependencies("find_service1.nasl", "mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)port = 3306;
ver=get_mysql_version(port:port);
if (isnull(ver)) exit(0);

if(ereg(pattern:"^3\.(([0-9]\..*)|(1[0-9]\..*)|(2(([0-2]\..*)|3\.(([0-9]$)|([0-4][0-9])|(5[0-5])))))",
	string:ver))security_hole(port);
