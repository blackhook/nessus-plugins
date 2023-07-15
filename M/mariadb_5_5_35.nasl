#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(72374);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2013-5908",
    "CVE-2014-0401",
    "CVE-2014-0412",
    "CVE-2014-0420",
    "CVE-2014-0437"
  );
  script_bugtraq_id(
    64849,
    64854,
    64864,
    64868,
    64873,
    64877,
    64880,
    64885,
    64888,
    64891,
    64893,
    64895,
    64896,
    64897,
    64898,
    64904,
    64908,
    65298,
    65312
  );

  script_name(english:"MariaDB 5.5 < 5.5.35 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.5 running on the remote host is a version
prior to 5.5.35. It is, therefore, potentially affected by the
following vulnerabilities :

  - Errors exist related to the following subcomponents :
    Error Handling, FTS, GIS, InnoDB, Locking, Optimizer,
    Partition, Performance Schema, Privileges, Replication,
    and Thread Pooling. (CVE-2013-5860, CVE-2013-5881,
    CVE-2013-5891, CVE-2013-5894, CVE-2013-5908,
    CVE-2014-0386, CVE-2014-0393, CVE-2014-0401,
    CVE-2014-0402, CVE-2014-0412, CVE-2014-0420,
    CVE-2014-0427, CVE-2014-0430, CVE-2014-0431,
    CVE-2014-0433, CVE-2014-0437)

  - An unspecified error exists related to stored
    procedures handling that could allow denial of service
    attacks. (CVE-2013-5882)

  - An error exists in the file 'client/mysql.cc' that
    could allow a buffer overflow leading to denial of
    service or possibly arbitrary code execution.
    (CVE-2014-0001)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5535-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-4974");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5353");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5356");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5396");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5405");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5406");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5453");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5458");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5461");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB 5.5.35 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");

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

mysql_check_version(variant:'MariaDB', fixed:'5.5.35-MariaDB', min:'5.5', severity:SECURITY_WARNING);
