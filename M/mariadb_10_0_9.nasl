#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72713);
  script_version("1.12");
  script_cvs_date("Date: 2019/10/21 11:55:47");

  script_cve_id(
    "CVE-2014-0384",
    "CVE-2014-2419",
    "CVE-2014-2432",
    "CVE-2014-2438",
    "CVE-2014-4243"
  );
  script_bugtraq_id(
    66835,
    66880,
    66875,
    66846,
    68611
  );

  script_name(english:"MariaDB 10 < 10.0.9 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of MariaDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 10 running on the remote host is a version
prior to 10.0.9. It is, therefore, potentially affected by denial of service vulnerabilities that can be exploited by
authenticated, remote attackers. These vulnerabilities are due to errors in several components, including the
following:

  - Partition (CVE-2014-2419)
  - Replication (CVE-2014-2438)
  - XML (CVE-2014-0384)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-1009-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2419");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Databases");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);
  exit(0); 
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.0.0-MariaDB', fixed:make_list('10.0.9-MariaDB'), severity:SECURITY_WARNING, paranoid: false);
