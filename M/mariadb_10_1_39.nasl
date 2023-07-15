#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129353);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2019-2614", "CVE-2019-2627");
  script_bugtraq_id(107927);

  script_name(english:"MariaDB 10.1.0 < 10.1.39 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MariaDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.1.39. It is, therefore, affected by the following
two vulnerabilities as referenced in the mdb-10139-rn advisory:

  - An unspecified vulnerability in the
    'Server: Security: Privileges' subcomponent could allow
    a high privileged attacker to hang or, via a frequently 
    repeatable crash, cause a complete denial of service.
    (CVE-2019-2627)

  - An unspecified vulnerability in the
    'Server: Security: Replication' subcomponent could
    allow a high privileged attacker to hang or, via a
    frequently repeatable crash, to cause a complete denial
    of service. (CVE-2019-2614)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10139-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.39 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2627");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.1.0-MariaDB', fixed:make_list('10.1.39-MariaDB'), severity:SECURITY_WARNING);
