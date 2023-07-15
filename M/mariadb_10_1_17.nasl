#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93610);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-6662");
  script_bugtraq_id(92912);
  script_xref(name:"EDB-ID", value:"40360");

  script_name(english:"MariaDB 10.1.x < 10.1.17 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.17. It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the check_log_path() function within
    file sql/sys_vars.cc due to inadequate restrictions on
    the ability to write to the my.cnf configuration file
    and allowing the loading of configuration files from
    path locations not used by current versions. An
    authenticated, remote attacker can exploit this issue
    by using specially crafted queries that utilize logging
    functionality to create new files or append custom
    content to existing files. This allows the attacker to
    gain root privileges by inserting a custom .cnf file
    with a 'malloc_lib=' directive pointing to specially
    crafted mysql_hookandroot_lib.so file and thereby cause
    MySQL to load a malicious library the next time it is
    started. (CVE-2016-6662)

  - A NULL pointer dereference flaw exists in the
    innobase_need_rebuild() function when handling renamed
    columns that allows an authenticated, remote attacker to
    crash the database, resulting in a denial of service.

  - A denial of service vulnerability exists in the
    ha_myisam::enable_indexes() function within file
    storage/myisam/ha_myisam.cc when handling ALTER TABLE
    statements. An authenticated, remote attacker can
    exploit this to crash the database.

  - A denial of service vulnerability exists in the
    Item_sum_std::val_real() function within file
    sql/item_sum.cc when handling SUM statements. An
    authenticated, remote attacker exploit this to crash the
    database.

  - A denial of service vulnerability exists within file
    sql/item_subselect.cc when handling specially crafted
    queries for non-existent functions. An authenticated,
    remote attacker can exploit this to crash the database.

  - A denial of service vulnerability exists in the
    Item_subselect::is_expensive() function within file
    sql/item_subselect.cc due to improper handling of
    optimization procedures. An authenticated, remote
    attacker can exploit this to crash the database.

  - A denial of service vulnerability exists in the
    st_select_lex_unit::cleanup() function within file
    sql/sql_union.cc when handling UNION queries during JOIN
    cleanup. An authenticated, remote attacker can exploit
    this to crash the database.");
  # https://mariadb.org/mariadb-10-1-17-mariadb-galera-cluster-10-0-27-now-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?074893a6");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10117-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10117-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-9304");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-10045");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-10419");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-10465");
  # http://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbd97f45");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6662");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/20");

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

mysql_check_version(variant:'MariaDB', fixed:'10.1.17-MariaDB', min:'10.1', severity:SECURITY_HOLE);
