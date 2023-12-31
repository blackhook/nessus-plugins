#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95877);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/03");

  script_cve_id(
    "CVE-2017-3238",
    "CVE-2017-3243",
    "CVE-2017-3244",
    "CVE-2017-3258",
    "CVE-2017-3265",
    "CVE-2017-3291",
    "CVE-2017-3312",
    "CVE-2017-3313",
    "CVE-2017-3317",
    "CVE-2017-3318"
  );
  script_bugtraq_id(
    95491,
    95501,
    95520,
    95527,
    95538,
    95560,
    95565,
    95571,
    95585,
    95588
  );

  script_name(english:"MySQL 5.5.x < 5.5.54 Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.54. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3238)

  - An unspecified flaw exists in the Charsets subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition. (CVE-2017-3243)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3244)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3258)

  - An unspecified flaw exists in the Packaging subcomponent
    that allows a local attacker to impact confidentiality
    and availability. (CVE-2017-3265)

  - Multiple unspecified flaws exist in the Packaging
    subcomponent that allow a local attacker to gain
    elevated privileges. (CVE-2017-3291, CVE-2017-3312)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to disclose sensitive
    information. (CVE-2017-3313)

  - An unspecified flaw exists in the Logging subcomponent
    that allows a local attacker to cause a denial of
    service condition. (CVE-2017-3317)

  - An unspecified flaw exists in the Error Handling
    subcomponent that allows a local attacker to disclose
    sensitive information. (CVE-2017-3318)

  - A local privilege escalation vulnerability exists in the
    mysqld_safe component due to unsafe use of the 'rm' and
    'chown' commands. A local attacker can exploit this to
    gain elevated privileges.

  - An unspecified flaw exists in the mysqld_safe component
    that allows an authenticated, remote attacker to have an
    unspecified impact.

  - An overflow condition exists in the Optimizer component
    due to improper validation of user-supplied input when
    handling nested expressions. An authenticated, remote
    attacker can exploit this to cause a stack-based buffer
    overflow, resulting in a denial of service condition.

  - An unspecified flaw exists when handling a CREATE TABLE
    query with a DATA DIRECTORY clause. An authenticated,
    remote attacker can exploit this to gain elevated
    privileges.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.oracle.com/epmos/faces/DocumentDisplay?id=2219938.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?092fb681");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3432537.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?724b555f");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-54.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3265");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

fix_version = "5.5.54";
exists_version = "5.5";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_server_only, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_WARNING);
