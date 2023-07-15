#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(72712);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2014-0384",
    "CVE-2014-2419",
    "CVE-2014-2432",
    "CVE-2014-2438",
    "CVE-2014-4243"
  );
  script_bugtraq_id(65757);

  script_name(english:"MariaDB 5.5 < 5.5.36 Multiple DoS Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.5 running on the remote host is a version
prior to 5.5.36. It is, therefore, potentially affected by denial of
service vulnerabilities due to errors related to the following :

  - Union queries
  - Prepare queries
  - Join::prepare queries
  - ONLY_FULL_GROUP_BY queries
  - 'unlock_row' function queries
  - NAME_CONST queries");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5536-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5505");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5581");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5617");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5629");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5655");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-714");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB 5.5.36 or later or apply the vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2419");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.36-MariaDB', min:'5.5', severity:SECURITY_WARNING);
