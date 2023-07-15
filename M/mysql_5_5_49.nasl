#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90682);
  script_version("1.14");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-0642",
    "CVE-2016-0643",
    "CVE-2016-0647",
    "CVE-2016-0648",
    "CVE-2016-0666",
    "CVE-2016-2047"
  );

  script_name(english:"MySQL 5.5.x < 5.5.49 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.49. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Federated subcomponent
    that allows an authenticated, remote attacker to impact
    integrity and availability. (CVE-2016-0642)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to disclose
    sensitive information. (CVE-2016-0643)

  - An unspecified flaw exists in the FTS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0647)

  - An unspecified flaw exists in the PS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0647)

  - An unspecified flaw exists in the Security: Privileges
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0666)

  - A man-in-the-middle spoofing vulnerability exists due to
    the server hostname not being verified to match a domain
    name in the Subject's Common Name (CN) or SubjectAltName
    field of the X.509 certificate. A man-in-the-middle
    attacker can exploit this, by spoofing the TLS/SSL
    server via a certificate that appears valid, to disclose
    sensitive information or manipulate transmitted data.
    (CVE-2016-2047)

  - A flaw exists related to certificate validation due to
    the server hostname not being verified to match a domain
    name in the X.509 certificate. A man-in-the-middle
    attacker can exploit this, by spoofing the TLS/SSL
    server via a certificate that appears valid, to disclose
    sensitive information or manipulate data.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb7b96f");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-49.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.49 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2047");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");

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

mysql_check_version(fixed:'5.5.49', min:'5.5', severity:SECURITY_WARNING);
