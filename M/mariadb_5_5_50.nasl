#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91767);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2016-3477",
    "CVE-2016-3521",
    "CVE-2016-3615",
    "CVE-2016-5440"
  );

  script_name(english:"MariaDB 5.5.x < 5.5.50 utf8mb4 Column Search DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 5.5.x prior to
5.5.50. It is, therefore, affected by a flaw in the
Item_func_match::fix_index() function within file sql/item_func.cc due
to improper handling of a full-text search of the utf8mb4 column. An
authenticated, remote attacker can exploit this to crash the server,
resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-5-5-50-updated-connectors-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5550-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5550-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-9986");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.50-MariaDB', min:'5.5', severity:SECURITY_WARNING);
