#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87210);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2015-4792",
    "CVE-2015-4802",
    "CVE-2015-4807",
    "CVE-2015-4815",
    "CVE-2015-4826",
    "CVE-2015-4830",
    "CVE-2015-4836",
    "CVE-2015-4858",
    "CVE-2015-4861",
    "CVE-2015-4870",
    "CVE-2015-4913",
    "CVE-2015-7744",
    "CVE-2016-3471"
  );
  script_bugtraq_id(
    77137,
    77145,
    77153,
    77165,
    77171,
    77190,
    77205,
    77208,
    77222,
    77228,
    77237
  );

  script_name(english:"MariaDB < 5.5.46 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is prior to 5.5.46.
It is, therefore, affected by the following vulnerabilities :

  - Multiple unspecified flaws exist related to the
    Partition subcomponent that allow an authenticated,
    remote attacker to cause a denial of service.
    (CVE-2015-4802, CVE-2015-4792)

  - An unspecified flaw exists related to the Query Cache
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2015-4807)

  - An unspecified flaw exists related to the DDL
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2015-4815)

  - An unspecified flaw exists related to the Types
    subcomponent that allows an authenticated, remote
    attacker to gain access to sensitive information.
    (CVE-2015-4826)

  - An unspecified flaw exists related to the
    Security:Privileges subcomponent that allows an
    authenticated, remote attacker to affect the integrity
    of the system. No other details are available.
    (CVE-2015-4830)

  - An unspecified flaw exists related to the SP
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2015-4836)

  - Multiple unspecified flaws exist related to the DML
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service. (CVE-2015-4858,
    CVE-2015-4913)

  - An unspecified flaw exists related to the InnoDB
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2015-4861)

  - An unspecified flaw exists related to the Parser
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2015-4870)

  - A flaw exists in the mysql_prepare_create_table()
    function due to improper handling of a comma buffer that
    is greater than zero. An authenticated, remote attacker
    can exploit this to cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-5-5-46-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-5546-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-5546-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-7050");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3471");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.46-MariaDB', severity:SECURITY_WARNING);
