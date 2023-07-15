#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2779 and 
# CentOS Errata and Security Advisory 2016:2779 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94981);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-2834", "CVE-2016-5285", "CVE-2016-8635");
  script_xref(name:"RHSA", value:"2016:2779");

  script_name(english:"CentOS 5 / 6 / 7 : nss / nss-util (CESA-2016:2779)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nss and nss-util is now available for Red Hat Enterprise
Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version:
nss (3.21.3), nss-util (3.21.3).

Security Fix(es) :

* Multiple buffer handling flaws were found in the way NSS handled
cryptographic data from the network. A remote attacker could use these
flaws to crash an application using NSS or, possibly, execute
arbitrary code with the permission of the user running the
application. (CVE-2016-2834)

* A NULL pointer dereference flaw was found in the way NSS handled
invalid Diffie-Hellman keys. A remote client could use this flaw to
crash a TLS/SSL server using NSS. (CVE-2016-5285)

* It was found that Diffie Hellman Client key exchange handling in NSS
was vulnerable to small subgroup confinement attack. An attacker could
use this flaw to recover private keys by confining the client DH key
to small subgroup of the desired group. (CVE-2016-8635)

Red Hat would like to thank the Mozilla project for reporting
CVE-2016-2834. The CVE-2016-8635 issue was discovered by Hubert Kario
(Red Hat). Upstream acknowledges Tyson Smith and Jed Davis as the
original reporter of CVE-2016-2834."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-November/022151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a63c1d2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-November/022152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19919c24"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-November/022159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?292c9a0a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003683.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?761aaeb0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8590820"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2834");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"nss-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.21.3-2.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"nss-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.21.3-1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.21.3-1.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-devel-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-sysinit-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-tools-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-3.21.3-1.1.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-devel-3.21.3-1.1.el7_3")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-devel / nss-pkcs11-devel / nss-sysinit / nss-tools / etc");
}
