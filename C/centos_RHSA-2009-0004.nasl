#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0004 and 
# CentOS Errata and Security Advisory 2009:0004 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35310);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0046", "CVE-2009-0047", "CVE-2009-0048", "CVE-2009-0049", "CVE-2009-0124", "CVE-2009-0125", "CVE-2009-0127", "CVE-2009-0128", "CVE-2009-0130");
  script_xref(name:"RHSA", value:"2009:0004");

  script_name(english:"CentOS 3 / 4 / 5 : openssl (CESA-2009:0004)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that correct a security issue are now
available for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength, general purpose, cryptography library.

The Google security team discovered a flaw in the way OpenSSL checked
the verification of certificates. An attacker in control of a
malicious server, or able to effect a 'man in the middle' attack,
could present a malformed SSL/TLS signature from a certificate chain
to a vulnerable client and bypass validation. (CVE-2008-5077)

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all running OpenSSL client applications must be
restarted, or the system rebooted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c2df4d6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3237a6d9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?699759fd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a33d5b8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015532.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccd277d4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015533.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aed7956"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66d8d2db"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe15c5e8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ef0e5b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015563.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c467ba9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(20, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl097a");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"openssl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-devel-0.9.7a-33.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-perl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl096b-0.9.6b-16.49")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-0.9.7a-43.17.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-devel-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-devel-0.9.7a-43.17.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-devel-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-perl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-perl-0.9.7a-43.17.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-perl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl096b-0.9.6b-22.46.c4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl097a-0.9.7a-9.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl096b / openssl097a");
}
