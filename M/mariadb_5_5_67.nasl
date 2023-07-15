#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133680);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/25");

  script_cve_id("CVE-2020-2574");

  script_name(english:"MariaDB 5.5.0 < 5.5.67 A Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 5.5.67. It is, therefore, affected by a vulnerability as
referenced in the mdb-5567-rn advisory.

  - Vulnerability in the MySQL Client product of Oracle
    MySQL (component: C API). Supported versions that are
    affected are 5.6.46 and prior, 5.7.28 and prior and
    8.0.18 and prior. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. CVSS
    3.0 Base Score 5.9 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2020-2574)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-5567-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.67 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2574");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
   script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'5.5.0-MariaDB', fixed:make_list('5.5.67-MariaDB'), severity:SECURITY_WARNING);