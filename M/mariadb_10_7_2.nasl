#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157459);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/20");

  script_cve_id(
    "CVE-2021-46659",
    "CVE-2022-0778",
    "CVE-2022-21595",
    "CVE-2022-24048",
    "CVE-2022-24050",
    "CVE-2022-24051",
    "CVE-2022-24052"
  );

  script_name(english:"MariaDB 10.7.0 < 10.7.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.7.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the mdb-1072-rn advisory.

  - This vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of the length of user-supplied data
    prior to copying it to a fixed-length heap-based buffer. An attacker can leverage this vulnerability to
    escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-16190.
    (CVE-2022-24052)

  - MariaDB before 10.7.2 allows an application crash because it does not recognize that
    SELECT_LEX::nest_level is local to each VIEW. (CVE-2021-46659)

  - This vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of the length of user-supplied data
    prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to
    escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-16191.
    (CVE-2022-24048)

  - This vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of validating the existence of an object prior to
    performing operations on the object. An attacker can leverage this vulnerability to escalate privileges
    and execute arbitrary code in the context of the service account. Was ZDI-CAN-16207. (CVE-2022-24050)

  - This vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of a user-supplied string before
    using it as a format specifier. An attacker can leverage this vulnerability to escalate privileges and
    execute arbitrary code in the context of the service account. Was ZDI-CAN-16193. (CVE-2022-24051)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-1072-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24052");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.7.0-MariaDB', fixed:make_list('10.7.2-MariaDB'), severity:SECURITY_WARNING);