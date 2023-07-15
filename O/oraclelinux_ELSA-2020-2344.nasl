#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2344 and 
# Oracle Linux Security Advisory ELSA-2020-2344 respectively.
#

include('compat.inc');

if (description)
{
  script_id(137037);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_xref(name:"RHSA", value:"2020:2344");

  script_name(english:"Oracle Linux 7 : bind (ELSA-2020-2344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2020:2344 :

The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2344 advisory.

  - bind: BIND does not sufficiently limit the number of
    fetches performed when processing referrals
    (CVE-2020-8616)

  - bind: A logic error in code which checks TSIG validity
    can be used to trigger an assertion failure in tsig.c
    (CVE-2020-8617)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-June/009985.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-chroot-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-export-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-export-libs-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-libs-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-libs-lite-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-license-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-lite-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-libs-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-utils-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-sdb-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-sdb-chroot-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-utils-9.11.4-16.P2.el7_8.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-export-devel / etc");
}
