#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17826);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2005-0799");

  script_name(english:"MySQL < 4.1.13 / 5.0.8 DOS Device Name Denial of Service Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
4.1.13 or 5.0.8. 

On Windows, a remote attacker can crash the server via a 'use' command
followed by MS-DOS device name, e.g. LPT1.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111091250923281&w=2");
  script_set_attribute(attribute:"see_also", value:"https://bugs.mysql.com/bug.php?id=9148");
  script_set_attribute(attribute:"see_also", value:"https://lists.mysql.com/internals/25190");
  script_set_attribute(attribute:"see_also", value:"https://lists.mysql.com/internals/24584");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/Mar/270");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.1.13 / 5.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os) exit(0, "The remote host is not running Windows.");
}

mysql_check_version(fixed:make_list('4.1.13', '5.0.8'), severity:SECURITY_WARNING);
