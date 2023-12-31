#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86660);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/03");

  script_cve_id(
    "CVE-2015-1793",
    "CVE-2015-4766",
    "CVE-2015-4819",
    "CVE-2015-4833",
    "CVE-2015-4879",
    "CVE-2015-4895",
    "CVE-2015-4904"
  );
  script_bugtraq_id(
    75652,
    77136,
    77140,
    77170,
    77196,
    77219,
    77232
  );

  script_name(english:"Oracle MySQL 5.6.x < 5.6.26 Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.6.x
prior to 5.6.26. It is, therefore, affected by the following
vulnerabilities :

  - A certificate validation bypass vulnerability exists in
    the Security:Encryption subcomponent due to a flaw in
    the X509_verify_cert() function in x509_vfy.c that is
    triggered when locating alternate certificate chains
    when the first attempt to build such a chain fails. A
    remote attacker can exploit this, by using a valid leaf
    certificate as a certificate authority (CA), to issue
    invalid certificates that will bypass authentication.
    (CVE-2015-1793)

  - An unspecified flaw exists in the Client Programs
    subcomponent. A local attacker can exploit this to gain
    elevated privileges. (CVE-2015-4819)

  - An unspecified flaw exists in the DLM subcomponent.
    An authenticated, remote attacker can exploit this to
    impact integrity. (CVE-2015-4879)

Additionally, unspecified denial of service vulnerabilities exist in
the following MySQL subcomponents :

  - InnoDB (CVE-2015-4895)

  - libmysqld (CVE-2015-4904)

  - Partition (CVE-2015-4833)

  - Security:Firewall (CVE-2015-4766)");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368795.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1de82df5");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-26.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2048227.1");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1793");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2020 Tenable Network Security, Inc.");
  script_family(english:"Databases");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");
  exit(0);
}

include("mysql_version.inc");

package_list = make_list(
  "mysql-community-client",
  "mysql-community-common",
  "mysql-community-devel",
  "mysql-community-embedded",
  "mysql-community-libs",
  "mysql-community-libs-compat",
  "mysql-community-server",
  "MySQL-client",
  "MySQL-client-advanced",
  "MySQL-devel",
  "MySQL-devel-advanced",
  "MySQL-shared",
  "MySQL-shared-advanced",
  "MySQL-shared-compat",
  "MySQL-shared-compat-advanced",
  "MySQL-server",
  "MySQL-server-advanced"
);
rhel_list = make_list(
  "EL5",
  "EL6",
  "EL7",
  "FC20",
  "FC21",
  "FC22",
  "FC23",
  "RHEL5",
  "RHEL6",
  "RHEL7",
  "SL5",
  "SL6",
  "SL7"
);
ala_list = make_list(
  "ALA"
);
suse_list = make_list(
  "SLED11",
  "SLED12",
  "SLES11",
  "SLES12",
  "SUSE13.1",
  "SUSE13.2"
);
centos_list = make_list(
  "CentOS-5",
  "CentOS-6",
  "CentOS-7"
);

fix_version = "5.6.26";
exists_version = "5.6";

mysql_check_rpms(mysql_packages:package_list, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:rhel_list, centos_os_list:centos_list, suse_os_list:suse_list, ala_os_list:ala_list, severity:SECURITY_HOLE);
