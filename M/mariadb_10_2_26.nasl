#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128974);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2758",
    "CVE-2019-2805",
    "CVE-2020-2922",
    "CVE-2021-2007"
  );
  script_bugtraq_id(109243, 109247);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"MariaDB 10.2.0 < 10.2.26 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.2.26. It is, therefore, affected by multiple
vulnerabilities as referenced in the mdb-10226-rn advisory.

  - A vulnerability in the 'Server: Pluggable Auth'
    subcomponent. This is an easily exploitable
    vulnerability that allows a highly privileged attacker
    with network access via multiple protocols to
    compromise the MariaDB Server. Successful attacks
    involving this vulnerability can result in the
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of the MariaDB Server.
    (CVE-2019-2737)

  - A vulnerability in the 'Server: Security: Privileges'
    subcomponent. This is an easily exploitable
    vulnerability that allows a highly privileged attacker,
    who is able to logon to the infrastructure where the
    MariaDB Server executes, to compromise the MariaDB
    Server. Successful attacks involving this vulnerability
    can result in the unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of
    MariaDB Server as well as unauthorized update, insert
    or delete access to some of the data accessible to the
    MariaDB Server. (CVE-2019-2739)

  - A vulnerability in the 'Server: XML' subcomponent. This
    is an easily exploitable vulnerability that allows a
    low privileged attacker with network access via multiple
    protocols to compromise a MariaDB Server.Successful
    attacks involving this vulnerability can result in the
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of the MariaDB Server.
    (CVE-2019-2740)

  - A vulnerability in the InnoDB subcomponent of the
    MariaDB Server. This is an easily exploitable
    vulnerability that allows a highly privileged attacker
    with network access via multiple protocols to compromise
    a MariaDB Server. Successful attacks involving this
    vulnerability can result in the unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of the MariaDB Server as well as unauthorized
    update, insert or delete access to some of the data
    accessible to the MariaDB Server. (CVE-2019-2758)

  - A vulnerability in the 'Server: Parser' subcomponent.
    This is an easily exploitable vulnerability that allows
    a low privileged attacker with network access via
    multiple protocols to compromise the MariaDB Server.
    Successful attacks involving this vulnerability can
    result in the unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of the
    MariaDB Server. (CVE-2019-2805)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10226-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.2.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/18");

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

mysql_check_version(variant: 'MariaDB', min:'10.2.0-MariaDB', fixed:make_list('10.2.26-MariaDB'), severity:SECURITY_WARNING, paranoid: false);
