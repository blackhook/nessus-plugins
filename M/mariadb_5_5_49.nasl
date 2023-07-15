#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93616);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-0643",
    "CVE-2016-0647",
    "CVE-2016-0648",
    "CVE-2016-0666",
    "CVE-2016-3452",
    "CVE-2016-5444"
  );
  script_bugtraq_id(
    86457,
    86486,
    86495,
    86509,
    91987,
    91999
  );

  script_name(english:"MariaDB 5.5.x < 5.5.49 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 5.5.x prior to
5.5.49. It is, therefore, affected by the following vulnerabilities :

  - An unspecified flaw exists in the DML component that
    allows an authenticated, remote attacker to disclose
    sensitive information. (CVE-2016-0643)

  - An unspecified flaw exists in the FTS component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0647)

  - An unspecified flaw exists in the PS component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0648)

  - An unspecified flaw exists in the Security: Privileges
    component that allows an authenticated, remote attacker
    to cause a denial of service condition. (CVE-2016-0666)

  - An unspecified flaw exists in the Encryption component
    that allows an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2016-3452)

  - An unspecified flaw exists in the Connection component
    that allows an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2016-5444)

  - A denial of service vulnerability exists in the
    my_decimal_precision_to_length_no_truncation() function
    within file item_cmpfunc.cc when handling SELECT CASE
    statements. An authenticated, remote attacker can
    exploit this to crash the database.

  - A buffer overflow condition exists in the
    audit_plugin_so_init() function within file
    plugin/server_audit/server_audit.c due to improper
    validation of user-supplied input. An authenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-5549-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5549-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.49 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
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

mysql_check_version(variant:'MariaDB', fixed:'5.5.49-MariaDB', min:'5.5', severity:SECURITY_WARNING);
