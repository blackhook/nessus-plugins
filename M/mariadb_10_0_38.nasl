#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129062);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2019-2529", "CVE-2019-2537");
  script_bugtraq_id(106619);

  script_name(english:"MariaDB 10.0.0 < 10.0.38 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.0.38. It is, therefore, affected by two
vulnerabilities as referenced in the mdb-10038-rn advisory. The vulnerabilities are as follows:

  - An unspecified vulnerability in MariaDB in the
    'Server: Optimizer' subcomponent could allow a low
    privileged attacker with network access via multiple
    protocols to perform a denial of service attack.
    (CVE-2019-2529)

  - An unspecified vulnerability in MariaDB in the
    'Server: DDL' subcomponent could allow a high
    privileged attacker with network access via multiple
    protocols to perform a denial of service attack.
    (CVE-2019-2537)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10038-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2537");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2529");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.0.0-MariaDB', fixed:make_list('10.0.38-MariaDB'), severity:SECURITY_WARNING, paranoid: false);
