#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95632);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2016-3492",
    "CVE-2016-5616",
    "CVE-2016-5624",
    "CVE-2016-5626",
    "CVE-2016-5629",
    "CVE-2016-6663",
    "CVE-2016-8283"
  );
  script_bugtraq_id(
    92911,
    93614,
    93635,
    93638,
    93650,
    93668,
    93737
  );

  script_name(english:"MariaDB 10.1.x < 10.1.18 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.18. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3492)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-5616)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5624)

  - An unspecified flaw exists in the GIS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5626)

  - An unspecified flaw exists in the Federated subcomponent
    that allows an authenticated remote attacker to cause a
    denial of service condition. (CVE-2016-5629)

  - A security bypass vulnerability exists that allows an
    authenticated, remote attacker to bypass file access
    restrictions and create the /var/lib/mysql/my.cnf file
    with arbitrary contents without the FILE privilege
    requirement. (CVE-2016-6663)

  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-8283)

  - A flaw exists in the Item_field::fix_after_pullout()
    function within file sql/item.cc when handling a
    prepared statement with conversion to semi-join. An
    authenticated, remote attacker can exploit this to cause
    a denial of service condition.

  - An assertion flaw exists in the mysql_admin_table()
    function within file sql/sql_admin.cc when handling
    the re-execution of certain ANALYZE TABLE prepared
    statements. An authenticated, remote attacker can
    exploit this to cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10118-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10118-changelog/");
  # https://mariadb.com/resources/blog/update-on-security-vulnerabilities-cve-2016-6663-and-cve-2016-6664-related-to-mariadb-server/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fefde198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6663");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.1.18-MariaDB', min:'10.1', severity:SECURITY_WARNING);
