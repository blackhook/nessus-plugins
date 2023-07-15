#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93810);
  script_version("1.8");
  script_cvs_date("Date: 2019/01/02 11:18:37");


  script_name(english:"MariaDB 10.1.x < 10.1.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.7. It is, therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists in the
    base_list_iterator::next_fast() function within file
    sql/sql_parse.cc when handling multi-table updates. An
    authenticated, remote attacker can exploit this to crash
    the server.

  - A denial of service vulnerability exists in the
    ACL_internal_schema_registry::lookup() function within
    file sql/sql_acl.cc when handling multi-table updates.
    An authenticated, remote attacker can exploit this to
    crash the server.

  - A denial of service vulnerability exists in the
    Item_func_group_concat::fix_fields() function within
    file sql/item_sum.cc when handling arguments on the
    second execution of PS. An authenticated, remote
    attacker can exploit this to crash the server.

  - A denial of service vulnerability exists in
    select_lex->non_agg_fields when using ONLY_FULL_GROUP_BY
    in a stored procedure or trigger that is repeatedly
    executed. An authenticated, remote attacker can exploit
    this to crash the server.

  - A buffer overflow condition exists within the
    my_multi_malloc() function when trying to allocate a key
    cache of more than 45G with a key_cache_block_size of
    1024 or less. An authenticated, remote attacker can
    exploit this to cause an unspecified impact.

  - A denial of service vulnerability exists within the
    page_cur_is_after_last() function when handling table
    alteration encryption keys. An authenticated, remote
    attacker can exploit this to crash the server.

  - A denial of service vulnerability exists within the
    Bitmap<64u>::merge() function when handling a specially
    crafted query. An authenticated, remote attacker can
    exploit this to crash the server.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-1017-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-1017-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

mysql_check_version(variant:'MariaDB', fixed:'10.1.7-MariaDB', min:'10.1', severity:SECURITY_HOLE);
