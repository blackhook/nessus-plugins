#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96489);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2016-6664",
    "CVE-2017-3238",
    "CVE-2017-3243",
    "CVE-2017-3244",
    "CVE-2017-3258",
    "CVE-2017-3265",
    "CVE-2017-3291",
    "CVE-2017-3312",
    "CVE-2017-3317",
    "CVE-2017-3318"
  );
  script_bugtraq_id(93612);

  script_name(english:"MariaDB 5.5.x < 5.5.54 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 5.5.x prior to
5.5.54. It is, therefore, affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists in
    scripts/mysqld_safe.sh due to improper handling of
    arguments to malloc-lib. A local attacker can exploit
    this, via a symlink attack on error logs, to gain root
    privileges. (CVE-2016-6664)

  - A denial of service vulnerability exists in
    sql/item_subselect.cc due to improper handling of
    queries from the select/unit tree. An authenticated,
    remote attacker can exploit this to crash the database.

  - A denial of service vulnerability exists in the
    check_well_formed_result() function in sql/item.cc due
    to improper handling of row validation. An
    authenticated, remote attacker can exploit this to crash
    the database.

  - A denial of service vulnerability exists in the
    parse_filter_rule() function in sql/rpl_filter.cc
    that is triggered during the clearing of wildcards. An
    authenticated, remote attacker can exploit this to crash
    the database.

  - A denial of service vulnerability exists in the
    safe_charset_converter() function in sql/item.cc due to
    improper handling of a specially crafted subselect query
    item. An authenticated, remote attacker can exploit this
    to crash the database.

  - A denial of service vulnerability exists in the
    st_select_lex::is_merged_child_of() function in
    sql/sql_lex.cc due to improper handling of merged views
    or derived tables. An authenticated, remote attacker can
    exploit this to crash the database.

  - A denial of service vulnerability exists in sql/item.cc
    due to improper handling of a specially crafted
    subquery. An authenticated, remote attacker can exploit
    this to crash the database.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-5554-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5554-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6664");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.54-MariaDB', min:'5.5', severity:SECURITY_WARNING);
