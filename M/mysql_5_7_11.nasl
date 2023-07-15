#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89056);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2015-3194",
    "CVE-2016-0640",
    "CVE-2016-0641",
    "CVE-2016-0644",
    "CVE-2016-0646",
    "CVE-2016-0649",
    "CVE-2016-0650",
    "CVE-2016-0652",
    "CVE-2016-0653",
    "CVE-2016-0654",
    "CVE-2016-0656",
    "CVE-2016-0658",
    "CVE-2016-0661",
    "CVE-2016-0663",
    "CVE-2016-0665",
    "CVE-2016-0668"
  );

  script_name(english:"MySQL 5.7.x < 5.7.11 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.11. It is, therefore, potentially affected by multiple
vulnerabilities :

  - A NULL pointer dereference flaw exists in the bundled
    version of OpenSSL in file rsa_ameth.c due to improper
    handling of ASN.1 signatures that are missing the PSS
    parameter. A remote attacker can exploit this to cause
    the signature verification routine to crash, resulting
    in a denial of service condition. (CVE-2015-3194)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to impact
    integrity and availability. (CVE-2016-0640)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows an authenticated, remote attacker to
    disclose sensitive information or cause a denial of
    service condition. (CVE-2016-0641)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0644)

  - Multiple unspecified flaws exist in the DML subcomponent
    that allow an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0646,
    CVE-2016-0652)

  - An unspecified flaw exists in the PS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0649)

  - An unspecified flaw exists in the Replication
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0650)

  - An unspecified flaw exists in the FTS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0653)

  - Multiple unspecified flaws exist in the InnoDB
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0654, CVE-2016-0656, CVE-2016-0668)

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0658)

  - An unspecified flaw exists in the Options subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0661)

  - An unspecified flaw exists in the Performance Schema
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0663)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0665)

  - A denial of service vulnerability exists in the bundled
    OpenSSL library due to improper handling of variables
    declared as TEXT or BLOB. An authenticated, remote
    attacker can exploit this to corrupt data or cause a
    denial of service condition.

  - A denial of service vulnerability exists that is
    triggered when handling a 'CREATE TEMPORARY TABLE ..
    SELECT' statement involving BIT columns. An
    authenticated, remote attacker can exploit this to
    create an improper table or cause the server to exit, 
    resulting in a denial of service condition.

  - A denial of service vulnerability exists due to improper
    handling of queries that contain 'WHERE 0'. An
    authenticated, remote attacker can exploit this to cause
    an uninitialized read, resulting in a denial of service
    condition.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-11.html");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0defed6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");

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

mysql_check_version(fixed:'5.7.11', min:'5.7', severity:SECURITY_WARNING);
