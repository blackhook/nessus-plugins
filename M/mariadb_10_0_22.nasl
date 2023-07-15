#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(86874);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2015-4792",
    "CVE-2015-4802",
    "CVE-2015-4807",
    "CVE-2015-4815",
    "CVE-2015-4826",
    "CVE-2015-4830",
    "CVE-2015-4836",
    "CVE-2015-4858",
    "CVE-2015-4861",
    "CVE-2015-4870",
    "CVE-2015-4913",
    "CVE-2015-7744",
    "CVE-2016-0610",
    "CVE-2016-3471"
  );

  script_name(english:"MariaDB 10.0.x < 10.0.22 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.0.x prior to
10.0.22. It is, therefore, affected by multiple vulnerabilities :

  - Multiple denial of service vulnerabilities exist due to
    multiple unspecified flaws in the 'Server : Partition'
    subcomponent. An authenticated, remote attacker can
    exploit these flaws to affect availability.
    (CVE-2015-4792, CVE-2015-4802)

  - A denial of service vulnerability exists due to an
    unspecified flaw in the Query Cache subcomponent. An
    authenticated, remote attacker can exploit this to
    affect availability. (CVE-2015-4807)

  - A denial of service vulnerability exists due to an
    unspecified flaw in the DDL subcomponent. An
    authenticated, remote attacker can exploit this to
    affect availability. (CVE-2015-4815)

  - An information disclosure vulnerability exists due to an
    unspecified flaw in the Types subcomponent. An
    authenticated, remote attacker can exploit this to gain
    access to sensitive information. (CVE-2015-4826)

  - An unspecified vulnerability exists due to an
    unspecified flaw in the 'Security : Privileges'
    subcomponent. An authenticated, remote attacker can
    exploit this to affect integrity. (CVE-2015-4830)

  - A denial of service vulnerability exists due to an
    unspecified flaw in the SP subcomponent. An
    authenticated, remote attacker can exploit this to
    affect availability. (CVE-2015-4836)

  - Multiple denial of service vulnerabilities exist due to
    multiple unspecified flaws in the DML subcomponent. An
    authenticated, remote attacker can exploit these flaws
    to affect availability. (CVE-2015-4858, CVE-2015-4913)

  - A denial of service vulnerability exists due to an
    unspecified flaw in the InnoDB subcomponent. An
    authenticated, remote attacker can exploit this to
    affect availability. (CVE-2015-4861)

  - A denial of service vulnerability exists due to an
    unspecified flaw in the 'Server : Parser' subcomponent.
    An authenticated, remote attacker can exploit this to
    affect availability. (CVE-2015-4870)

  - A denial of service vulnerability exists due to a flaw
    in the ha_partition::index_init() function that is
    triggered when handling the priority queue. An
    authenticated, remote attacker can exploit this, via a
    specially crafted query, to cause the database to crash.

  - A denial of service vulnerability exists due to a flaw
    in the Item_field::fix_outer_field() function that is
    triggered when handling PREPARE statements. An
    authenticated, remote attacker can exploit this, via a
    specially crafted query, to cause the database to crash.

  - A denial of service vulnerability exists due to a flaw
    in the convert_kill_to_deadlock_error() function that is
    triggered when handling rollbacks. An authenticated, 
    remote attacker can exploit this, via a specially
    crafted query, to cause the database to crash.

  - A denial of service vulnerability exists due to a flaw
    in the no_rows_in_result() function that is triggered
    when handling logical conditions. An authenticated,
    remote attacker can exploit this, via a specially
    crafted query, to cause the database to crash.

  - A denial of service vulnerability exists due to a flaw
    in the handle_grant_struct() function that is triggered
    when handling HASH updates. An authenticated, remote
    attacker can exploit this, via a specially crafted
    query, to cause the database to crash.

  - A denial of service vulnerability exists due to a flaw
    in the is_invalid_role_name() function that is triggered
    when handling ACLs with blank role names. An
    authenticated, remote attacker can exploit this, via a
    specially crafted query, to cause the database to crash.

  - A denial of service vulnerability exists due to a flaw
    in the Item_direct_view_ref class that is triggered
    when handling SELECT queries. An authenticated, remote
    attacker can exploit this, via a specially crafted
    query, to cause the database to crash.

  - A denial of service vulnerability exists due to a flaw
    in the opt_sum_query() function that is triggered when
    handling constant tables. An authenticated, remote
    attacker can exploit this, via a specially crafted
    query, to cause the database to crash.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-10-0-22-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8805");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8756");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8725");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8609");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8624");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8614");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8525");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-7930");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3471");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.0.22-MariaDB', min:'10.0', severity:SECURITY_WARNING);
