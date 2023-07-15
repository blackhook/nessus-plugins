#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109171);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/03");

  script_cve_id(
    "CVE-2018-2755",
    "CVE-2018-2758",
    "CVE-2018-2759",
    "CVE-2018-2761",
    "CVE-2018-2762",
    "CVE-2018-2766",
    "CVE-2018-2769",
    "CVE-2018-2771",
    "CVE-2018-2773",
    "CVE-2018-2775",
    "CVE-2018-2776",
    "CVE-2018-2777",
    "CVE-2018-2778",
    "CVE-2018-2779",
    "CVE-2018-2780",
    "CVE-2018-2781",
    "CVE-2018-2782",
    "CVE-2018-2784",
    "CVE-2018-2786",
    "CVE-2018-2787",
    "CVE-2018-2810",
    "CVE-2018-2812",
    "CVE-2018-2813",
    "CVE-2018-2816",
    "CVE-2018-2817",
    "CVE-2018-2818",
    "CVE-2018-2819",
    "CVE-2018-2839",
    "CVE-2018-2846"
  );
  script_bugtraq_id(
    103777,
    103778,
    103779,
    103780,
    103781,
    103783,
    103785,
    103786,
    103787,
    103789,
    103802,
    103804,
    103814,
    103824,
    103828,
    103830
  );

  script_name(english:"MySQL 5.7.x < 5.7.22 Multiple Vulnerabilities (RPM Check) (April 2018 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.22. It is, therefore, affected by multiple vulnerabilities as
noted in the April 2018 Critical Patch Update advisory. Please consult
the CVRF details for the applicable CVEs for additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-22.html");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/4422902.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64303a9a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2812");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/19");

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

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

fix_version = "5.7.22";
exists_version = "5.7";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_all, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_WARNING);
