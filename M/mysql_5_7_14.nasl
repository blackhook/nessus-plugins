#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93004);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-3495",
    "CVE-2016-5612",
    "CVE-2016-5627",
    "CVE-2016-5628",
    "CVE-2016-5630",
    "CVE-2016-5631",
    "CVE-2016-5633",
    "CVE-2016-5634",
    "CVE-2016-5635",
    "CVE-2016-8284",
    "CVE-2016-8287",
    "CVE-2016-8289",
    "CVE-2016-8290"
  );
  script_bugtraq_id(
    93630,
    93642,
    93662,
    93670,
    93674,
    93684,
    93702,
    93709,
    93715,
    93720,
    93727,
    93733,
    93755
  );

  script_name(english:"MySQL 5.7.x < 5.7.14 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.14. It is, therefore, affected by multiple vulnerabilities :

  - Multiple unspecified flaws exist in the InnoDB
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3495, CVE-2016-5627, CVE-2016-5630)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5612)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5628)

  - An unspecified flaw exists in the Memcached
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5631)

  - Multiple unspecified flaws exist in the Performance
    Schema subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5633, CVE-2016-8290)

  - An unspecified flaw exists in the RBR subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5634)

  - An unspecified flaw exists in the Security: Audit
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5635)

  - An unspecified flaw exists in the Replication
    subcomponent that allows a local attacker to cause a
    denial of service condition. (CVE-2016-8284)

  - An unspecified flaw exists in the Replication
    subcomponent that allows a authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-8287)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows a local attacker to impact integrity and
    availability. (CVE-2016-8289)

  - A denial of service vulnerability exists in InnoDB when
    selecting full-text index information schema tables for
    a deleted table. An authenticated, remote attacker can
    exploit this to cause a segmentation fault.

  - A denial of service vulnerability exists in InnoDB when
    handling ALTER TABLE operations on tables that have an
    indexed virtual column. An authenticated, remote
    attacker can exploit this to cause an assertion failure,
    resulting in a server crash.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.7.14', min:'5.7', severity:SECURITY_NOTE);
