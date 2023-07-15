#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1842 and 
# CentOS Errata and Security Advisory 2017:1842 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102734);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-7970", "CVE-2014-7975", "CVE-2015-8839", "CVE-2015-8970", "CVE-2016-10088", "CVE-2016-10147", "CVE-2016-10200", "CVE-2016-10741", "CVE-2016-6213", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-8645", "CVE-2016-9576", "CVE-2016-9588", "CVE-2016-9604", "CVE-2016-9685", "CVE-2016-9806", "CVE-2017-1000379", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5551", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7495", "CVE-2017-7616", "CVE-2017-7889", "CVE-2017-8797", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_xref(name:"RHSA", value:"2017:1842");

  script_name(english:"CentOS 7 : kernel (CESA-2017:1842) (Stack Clash)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* An use-after-free flaw was found in the Linux kernel which enables a
race condition in the L2TPv3 IP Encapsulation feature. A local user
could use this flaw to escalate their privileges or crash the system.
(CVE-2016-10200, Important)

* A flaw was found that can be triggered in keyring_search_iterator in
keyring.c if type->match is NULL. A local user could use this flaw to
crash the system or, potentially, escalate their privileges.
(CVE-2017-2647, Important)

* It was found that the NFSv4 server in the Linux kernel did not
properly validate layout type when processing NFSv4 pNFS LAYOUTGET and
GETDEVICEINFO operands. A remote attacker could use this flaw to
soft-lockup the system and thus cause denial of service.
(CVE-2017-8797, Important)

This update also fixes multiple Moderate and Low impact security
issues :

* CVE-2015-8839, CVE-2015-8970, CVE-2016-9576, CVE-2016-7042,
CVE-2016-7097, CVE-2016-8645, CVE-2016-9576, CVE-2016-9588,
CVE-2016-9806, CVE-2016-10088, CVE-2016-10147, CVE-2017-2596,
CVE-2017-2671, CVE-2017-5970, CVE-2017-6001, CVE-2017-6951,
CVE-2017-7187, CVE-2017-7616, CVE-2017-7889, CVE-2017-8890,
CVE-2017-9074, CVE-2017-8890, CVE-2017-9075, CVE-2017-8890,
CVE-2017-9076, CVE-2017-8890, CVE-2017-9077, CVE-2017-9242,
CVE-2014-7970, CVE-2014-7975, CVE-2016-6213, CVE-2016-9604,
CVE-2016-9685

Documentation for these issues is available from the Release Notes
document linked from the References section.

Red Hat would like to thank Igor Redko (Virtuozzo) and Andrey Ryabinin
(Virtuozzo) for reporting CVE-2017-2647; Igor Redko (Virtuozzo) and
Vasily Averin (Virtuozzo) for reporting CVE-2015-8970; Marco Grassi
for reporting CVE-2016-8645; and Dmitry Vyukov (Google Inc.) for
reporting CVE-2017-2596. The CVE-2016-7042 issue was discovered by
Ondrej Kozina (Red Hat); the CVE-2016-7097 issue was discovered by
Andreas Gruenbacher (Red Hat) and Jan Kara (SUSE); the CVE-2016-6213
and CVE-2016-9685 issues were discovered by Qian Cai (Red Hat); and
the CVE-2016-9604 issue was discovered by David Howells (Red Hat).

Additional Changes :

For detailed information on other changes in this release, see the Red
Hat Enterprise Linux 7.4 Release Notes linked from the References
section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eefc4264"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8797");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-693.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-693.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-devel / kernel-devel / etc");
}
