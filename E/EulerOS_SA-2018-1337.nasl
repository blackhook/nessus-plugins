#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118425);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id(
    "CVE-2017-3636",
    "CVE-2017-3641",
    "CVE-2017-3651",
    "CVE-2017-3653",
    "CVE-2017-10268",
    "CVE-2017-10378",
    "CVE-2017-10379",
    "CVE-2017-10384",
    "CVE-2018-2622",
    "CVE-2018-2640",
    "CVE-2018-2665",
    "CVE-2018-2668",
    "CVE-2018-2755",
    "CVE-2018-2761",
    "CVE-2018-2767",
    "CVE-2018-2771",
    "CVE-2018-2781",
    "CVE-2018-2813",
    "CVE-2018-2817",
    "CVE-2018-2819"
  );

  script_name(english:"EulerOS Virtualization 2.5.1 : mariadb (EulerOS-SA-2018-1337)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - mysql: Client programs unspecified vulnerability (CPU
    Jul 2017) (CVE-2017-3636)

  - mysql: Server: DML unspecified vulnerability (CPU Jul
    2017) (CVE-2017-3641)

  - mysql: Client mysqldump unspecified vulnerability (CPU
    Jul 2017) (CVE-2017-3651)

  - mysql: Server: Replication unspecified vulnerability
    (CPU Oct 2017) (CVE-2017-10268)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Oct 2017) (CVE-2017-10378)

  - mysql: Client programs unspecified vulnerability (CPU
    Oct 2017) (CVE-2017-10379)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct
    2017) (CVE-2017-10384)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan
    2018) (CVE-2018-2622)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Jan 2018) (CVE-2018-2640)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Jan 2018) (CVE-2018-2665)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Jan 2018) (CVE-2018-2668)

  - mysql: Server: Replication unspecified vulnerability
    (CPU Apr 2018) (CVE-2018-2755)

  - mysql: Client programs unspecified vulnerability (CPU
    Apr 2018) (CVE-2018-2761)

  - mysql: Server: Locking unspecified vulnerability (CPU
    Apr 2018) (CVE-2018-2771)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Apr 2018) (CVE-2018-2781)

  - mysql: Server: DDL unspecified vulnerability (CPU Apr
    2018) (CVE-2018-2813)

  - mysql: Server: DDL unspecified vulnerability (CPU Apr
    2018) (CVE-2018-2817)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2018)
    (CVE-2018-2819)

  - mysql: Server: DDL unspecified vulnerability (CPU Jul
    2017) (CVE-2017-3653)

  - mysql: use of SSL/TLS not enforced in libmysqld (Return
    of BACKRONYM) (CVE-2018-2767)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1337
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1739e7a7");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.5.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["mariadb-5.5.60-1.h1",
        "mariadb-libs-5.5.60-1.h1",
        "mariadb-server-5.5.60-1.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
