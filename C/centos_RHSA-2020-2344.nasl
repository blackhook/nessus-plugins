#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:2344 and 
# CentOS Errata and Security Advisory 2020:2344 respectively.
#

include('compat.inc');

if (description)
{
  script_id(137007);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_xref(name:"RHSA", value:"2020:2344");

  script_name(english:"CentOS 7 : bind (CESA-2020:2344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2344 advisory.

  - bind: BIND does not sufficiently limit the number of
    fetches performed when processing referrals
    (CVE-2020-8616)

  - bind: A logic error in code which checks TSIG validity
    can be used to trigger an assertion failure in tsig.c
    (CVE-2020-8617)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2020-June/035744.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a940b1a");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-chroot-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-export-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-export-libs-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-libs-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-libs-lite-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-license-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-lite-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-devel-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-libs-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-utils-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-sdb-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-sdb-chroot-9.11.4-16.P2.el7_8.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-utils-9.11.4-16.P2.el7_8.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-export-devel / etc");
}
