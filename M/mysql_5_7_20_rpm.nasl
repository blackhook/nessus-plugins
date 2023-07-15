#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103967);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/03");

  script_cve_id(
    "CVE-2017-10155",
    "CVE-2017-10165",
    "CVE-2017-10167",
    "CVE-2017-10227",
    "CVE-2017-10268",
    "CVE-2017-10276",
    "CVE-2017-10283",
    "CVE-2017-10286",
    "CVE-2017-10294",
    "CVE-2017-10311",
    "CVE-2017-10313",
    "CVE-2017-10314",
    "CVE-2017-10320",
    "CVE-2017-10379",
    "CVE-2017-10384",
    "CVE-2018-2562",
    "CVE-2018-2591"
  );
  script_bugtraq_id(
    101314,
    101337,
    101390,
    101397,
    101402,
    101406,
    101410,
    101415,
    101420,
    101424,
    101433,
    101441,
    101444,
    101446,
    101448,
    102713,
    102714
  );

  script_name(english:"MySQL 5.7.x < 5.7.20 Multiple Vulnerabilities (RPM Check) (Oct 2017 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.20. It is, therefore, affected by multiple vulnerabilities as
noted in the October 2017 Critical Patch Update advisory. Please
consult the CVRF details for the applicable CVEs for additional
information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-20.html");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2307762.1");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3937099.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9f2a38");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

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

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

fix_version = "5.7.20";
exists_version = "5.7";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_all, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_HOLE);
