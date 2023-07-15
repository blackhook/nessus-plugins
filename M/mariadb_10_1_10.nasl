#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87726);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

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
    "CVE-2016-0642",
    "CVE-2016-0651",
    "CVE-2016-2047"
  );

  script_name(english:"MariaDB 10.1.x < 10.1.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.10. It is, therefore, affected by multiple vulnerabilities :

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
    
  - A race condition exists due to debian.cnf being created
    with world-readable permissions for a small period of
    time during initial installation. A local attacker can
    exploit this to disclose the debian-sys-maint password.

  - A flaw exists in the decimal2string() function due to
    improper handling of decimal precision greater than 40.
    An authenticated, remote attacker can exploit this to
    crash the server, resulting in a denial of service
    condition.

  - A security bypass vulnerability exists due to an
    incorrect implementation of the --ssl-verify-server-cert
    option. A man-in-the-middle attacker can exploit this to
    replace the server SSL certificate, resulting in a
    bypass of the client-side hostname verification.
    (MDEV-9212)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10110-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8407");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-9081");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-9212");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0546");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-2047");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.1.10-MariaDB', min:'10.1', severity:SECURITY_HOLE);
