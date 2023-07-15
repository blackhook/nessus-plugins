#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129360);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/21 11:55:47");

  script_cve_id(
    "CVE-2013-5908",
    "CVE-2014-0401",
    "CVE-2014-0412",
    "CVE-2014-0420",
    "CVE-2014-0437"
  );
  script_bugtraq_id(
    64896,
    64898,
    64880,
    64888,
    64849
  );

  script_name(english:"MariaDB 10.0.0 < 10.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MariaDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.0.8. It is, therefore, affected by Denial of
Service (DOS) vulnerabilities as referenced in the mariadb-1008-release-notes advisory due to errors in the following 
vectors:

  - Error Handling (CVE-2013-5908)
  - InnoDB (CVE-2014-0412)
  - Replication (CVE-2014-0420)
  - Optimizer (CVE-2014-0437)
  - Unknown vectors (CVE-2014-0401)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-1008-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0412");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");

	script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Databases");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);
  exit(0); 
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.0.0-MariaDB', fixed:make_list('10.0.8-MariaDB'), severity:SECURITY_WARNING);
