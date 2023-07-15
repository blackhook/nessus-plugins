#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101819);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2017-3635",
    "CVE-2017-3636",
    "CVE-2017-3641",
    "CVE-2017-3648",
    "CVE-2017-3651",
    "CVE-2017-3652",
    "CVE-2017-3653"
  );
  script_bugtraq_id(
    99730,
    99736,
    99767,
    99789,
    99802,
    99805,
    99810
  );

  script_name(english:"MySQL 5.5.x < 5.5.57 Multiple Vulnerabilities (July 2017 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.57. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Connector/C and C API
    components that allow an authenticated, remote attacker
    to cause a denial of service condition. (CVE-2017-3635)

  - An unspecified flaw exists in the Client programs
    component that allows a local attacker to impact
    confidentiality, integrity, and availability.
    (CVE-2017-3636)

  - An unspecified flaw exists in the DML component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3641)

  - An unspecified flaw exists in the Charsets component
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3648)

  - An unspecified flaw exists in the Client mysqldump
    component that allows an authenticated, remote attacker
    to impact integrity. (CVE-2017-3651)

  - Multiple unspecified flaws exist in the DDL component
    that allow an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-3652,
    CVE-2017-3653)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-57.html");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  # https://support.oracle.com/epmos/faces/DocumentDisplay?id=2279658.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d520c6c8");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3809960.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?322067e2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.57 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3652");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.57', min:'5.5', severity:SECURITY_WARNING);
