##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148828);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2021-27928");

  script_name(english:"MariaDB 10.3.0 < 10.3.28 A Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.3.28. It is, therefore, affected by a vulnerability
as referenced in the mdb-10328-rn advisory.

  - A remote code execution issue was discovered in MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4
    before 10.4.18, and 10.5 before 10.5.9; Percona Server through 2021-03-03; and the wsrep patch through
    2021-03-03 for MySQL. An untrusted search path leads to eval injection, in which a database SUPER user can
    execute OS commands after modifying wsrep_provider and wsrep_notify_cmd. NOTE: this does not affect an
    Oracle product. (CVE-2021-27928)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10328-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.3.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27928");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.3.0-MariaDB', fixed:make_list('10.3.28-MariaDB'), severity:SECURITY_HOLE);