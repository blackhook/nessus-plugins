#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84796);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2015-2582",
    "CVE-2015-2620",
    "CVE-2015-2643",
    "CVE-2015-2648",
    "CVE-2015-3152",
    "CVE-2015-4752",
    "CVE-2015-4864"
  );
  script_bugtraq_id(
    74398,
    75751,
    75822,
    75830,
    75837,
    75849,
    77187
  );

  script_name(english:"MariaDB 10.0.x < 10.0.20 Multiple Vulnerabilities (BACKRONYM)");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.0.x prior to
10.0.20. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the GIS component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2015-2582)

  - An unspecified flaw exists in the Security: Privileges
    component that allows an authenticated, remote attacker
    to disclose sensitive information. (CVE-2015-2620)

  - An unspecified flaw exists in the Optimizer component
    that allows an authenticated, remote attacker
    to cause a denial of service condition. (CVE-2015-2643)

  - An unspecified flaw exists in the DML component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2015-2648)

  - A security feature bypass vulnerability, known as
    'BACKRONYM', exists due to a failure to properly enforce
    the requirement of an SSL/TLS connection when the --ssl
    client option is used. A man-in-the-middle attacker can
    exploit this flaw to coerce the client to downgrade to
    an unencrypted connection, allowing the attacker to
    disclose data from the database or manipulate database
    queries. (CVE-2015-3152)

  - An unspecified flaw exists in the I_S component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2015-4752)

  - An unspecified flaw exists in the Security: Privileges
    component that allows an authenticated, remote attacker
    to impact integrity. (CVE-2015-4864)

  - A denial of service vulnerability exists in the
    get_server_from_table_to_cache() function within file
    sql/sql_servers.cc when handling empty names. An
    authenticated attacker, remote attacker can exploit
    this to crash the server.

  - A denial of service vulnerability exists when updating
    leaf tables with JOIN during list storing. An
    authenticated, remote attacker can exploit this to crash
    the server.

  - A denial of service vulnerability exists within file
    ha_innodb.cc when handling concurrent multi-table
    updates. An authenticated, remote attacker can exploit
    this to crash the server.

  - An out-of-bounds read error exists in the
    escape_string_hide_passwords() function within file
    plugin/server_audit/server_audit.c when handling
    specially crafted SET PASSWORD queries. An
    authenticated, remote attacker can exploit this to
    disclose memory contents or cause a denial of service
    condition.

  - A denial of service vulnerability exists in the
    wait_for_workers_idle() function within file
    rpl_parallel.cc when handling worker threads. An
    authenticated attacker, remote attacker can exploit this
    to crash the database.

  - A denial of service vulnerability exists in
    sys_var_pluginvar::plugin due to improper
    initialization, leading to a race condition between
    INSTALL PLUGIN and SET that results in an uninitialized
    memory reference. An authenticated attacker, remote
    attacker can exploit this to crash the database.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10020-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10020-changelog/");
  script_set_attribute(attribute:"see_also", value:"http://backronym.fail/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3152");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.0.20-MariaDB', min:'10.0', severity:SECURITY_WARNING);
