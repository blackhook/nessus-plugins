#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(99670);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id("CVE-2017-3302", "CVE-2017-3313");
  script_bugtraq_id(
    95527,
    96162,
    97725,
    97742,
    97776,
    97818,
    97831
  );

  script_name(english:"MariaDB 5.5.x < 5.5.55 / 10.0.x < 10.0.30 / 10.1.x < 10.1.22 / 10.2.x < 10.2.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 5.5.x prior to
5.5.55, 10.0.x prior to 10.0.30, 10.1.x prior to 10.1.22, or 10.2.x
prior to 10.2.5. It is, therefore, affected by multiple
vulnerabilities :

  - A use-after-free error exists in file client.c in the
    mysql_prune_stmt_list() function that allows an
    unauthenticated, remote attacker to crash the database.
    (CVE-2017-3302)

  - Multiple unspecified flaws exist in the DML subcomponent
    that allow an authenticated, remote attacker to cause a
    denial of service condition. Note that these issues only
    affect version 5.5.x. (CVE-2017-3308, CVE-2017-3456)

  - Multiple unspecified flaws exist in the Optimizer
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition. Note
    that these issues only affect version 5.5.x.
    (CVE-2017-3309, CVE-2017-3453)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to disclose sensitive
    information. (CVE-2017-3313)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to impact
    integrity. Note that this issue only affects version
    5.5.x. (CVE-2017-3464)

  - A denial of service vulnerability exists in the
    Field_time::store_TIME_with_warning() function when
    handling specially crafted INSERT queries. An
    authenticated, remote attacker can exploit this to
    crash the database. Note that this issue only affects
    versions 5.5.x and 10.0.x.

  - A denial of service vulnerability exists in the
    JOIN_CACHE::create_remaining_fields() function in file
    sql_join_cache.cc when handling data caching. An
    authenticated, remote attacker can exploit this to crash
    the database.

  - A denial of service vulnerability exists in the
    SJ_TMP_TABLE::create_sj_weedout_tmp_table() function
    in file opt_subselect.cc when handling specially crafted
    WHERE queries. An authenticated, remote attacker can
    exploit this to crash the database. Note that this issue
    only affects versions 10.0.x and 10.1.x.

  - A denial of service vulnerability exists in the
    ha_partition::reset() function in file ha_partition.cc
    when handling specially crafted SELECT queries. An
    authenticated, remote attacker can exploit this to
    crash the database.

  - A denial of service vulnerability exists in the
    find_field_in_tables() function in file sql_base.cc when
    handling stored procedures in EXISTS queries. An
    authenticated, remote attacker can exploit this to crash
    the database. Note that this issue only affects versions
    10.0.x, 10.1.x, and 10.2.x.

  - A denial of service vulnerability exists in the
    JOIN::drop_unused_derived_keys() function in file
    sql_select.cc when handling specially crafted SELECT
    statements. An authenticated, remote attacker can
    exploit this to crash the database. Note that this issue
    only affects versions 5.5.x, 10.1.x, and 10.2.x.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5555-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10030-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10122-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-1025-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-5555-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10030-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10122-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-1025-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.55 / 10.0.30 / 10.1.22 / 10.2.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3313");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

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

mysql_check_version(variant:'MariaDB', fixed:make_list('10.0.30-MariaDB', '5.5.55-MariaDB', '10.1.22-MariaDB', '10.2.5-MariaDB'), severity:SECURITY_NOTE);
