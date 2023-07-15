#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87419);
  script_version("1.19");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-0505",
    "CVE-2016-0546",
    "CVE-2016-0596",
    "CVE-2016-0597",
    "CVE-2016-0598",
    "CVE-2016-0600",
    "CVE-2016-0606",
    "CVE-2016-0608",
    "CVE-2016-0609",
    "CVE-2016-0616",
    "CVE-2016-0651"
  );

  script_name(english:"MySQL 5.5.x < 5.5.47 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.47. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Server : Options
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0505)

  - An unspecified flaw exists in the Client subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-0546)

  - An unspecified flaw exists in the Server : DML
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0596)

  - Multiple unspecified flaws exist in the Server :
    Optimizer subcomponent that allows an authenticated,
    remote attacker to cause a denial of service.
    (CVE-2016-0597, CVE-2016-0598, CVE-2016-0616)

  - An unspecified flaw exists in the Server : InnoDB
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0600)

  - An unspecified flaw exists in the Server : Security :
    Encryption subcomponent that allows an authenticated,
    remote attacker to impact integrity. (CVE-2016-0606,
    CVE-2016-0609)

  - An unspecified flaw exists in the Server : UDF
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0608)

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0651)
    
  - A denial of service vulnerability exists due to
    repeatedly executing a prepared statement when the
    default database has been changed. An authenticated,
    remote attacker can exploit this to cause the server to
    exit.

  - A denial of service vulnerability exists that is
    triggered when updating views using ALL comparison
    operators on subqueries that select from indexed columns
    in the main table. An authenticated, remote attacker can
    exploit this to cause the server to exit, resulting in a
    denial of service condition.

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input to the
    strcpy() and sprintf() functions. An authenticated,
    remote attacker can exploit this to cause a buffer
    overflow, resulting in a denial of service condition or
    the execution of arbitrary code.

  - A denial of service vulnerability exists that is
    triggered when handling concurrent FLUSH PRIVILEGES and
    REVOKE or GRANT statements. An authenticated, remote
    attacker can exploit this to cause the server to exit by
    triggering an invalid memory access to proxy user
    information.

  - A denial of service vulnerability exists that is
    triggered on the second execution of a prepared
    statement where an ORDER BY clause references a column
    position. An authenticated, remote attacker can exploit
    this to cause the server to exit.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-47.html");
  # https://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6405bf15");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0defed6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.47 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0546");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.47', min:'5.5', severity:SECURITY_HOLE);
