#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128876);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/21 11:55:47");

  script_cve_id("CVE-2019-2510", "CVE-2019-2537");
  script_bugtraq_id(106627, 106619);

  script_name(english:"MariaDB 10.3.0 < 10.3.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MariaDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.3.13. It is, therefore, affected by two 
vulnerabilities as referenced in the mdb-10313-rn advisory. They are as follows:

  - A vulnerability in the 'Server: DDL' subcomponent. This is an easily exploitable vulnerability that allows a highly
    privileged attacker with network access via multiple protocols to compromise the MariaDB server. Successful attacks
    involving this vulnerability result in the unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of the MariaDB Server. (CVE-2019-2537)

  - A vulnerability in the 'InnoDB' subcomponent. This is an easily exploitable vulnerability that allows a highly
    privileged attacker with network access via multiple network protocols to compromise the MariaDB Server. Successful
    attacks involving this vulnerability result in the unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of the MariaDB Server. (CVE-2019-2510)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10313-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.3.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2537");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Databases");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);
  exit(0); 
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.3.0-MariaDB', fixed:make_list('10.3.13-MariaDB'), severity:SECURITY_WARNING, paranoid: false);
