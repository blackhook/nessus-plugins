#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0769 and 
# CentOS Errata and Security Advisory 2013:0769 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66217);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914");
  script_bugtraq_id(57638, 58839);
  script_xref(name:"RHSA", value:"2013:0769");

  script_name(english:"CentOS 5 : glibc (CESA-2013:0769)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues and two bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

It was found that getaddrinfo() did not limit the amount of stack
memory used during name resolution. An attacker able to make an
application resolve an attacker-controlled hostname or IP address
could possibly cause the application to exhaust all stack memory and
crash. (CVE-2013-1914)

A flaw was found in the regular expression matching routines that
process multibyte character input. If an application utilized the
glibc regular expression matching mechanism, an attacker could provide
specially crafted input that, when processed, would cause the
application to crash. (CVE-2013-0242)

This update also fixes the following bugs :

* The improvements RHSA-2012:1207 made to the accuracy of floating
point functions in the math library caused performance regressions for
those functions. The performance regressions were analyzed and a fix
was applied that retains the current accuracy but reduces the
performance penalty to acceptable levels. Refer to Red Hat Knowledge
solution 229993, linked to in the References, for further information.
(BZ#950535)

* It was possible that a memory location freed by the localization
code could be accessed immediately after, resulting in a crash. The
fix ensures that the application does not crash by avoiding the
invalid memory access. (BZ#951493)

Users of glibc are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-April/019706.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?017c7356"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0242");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"glibc-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-common-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-devel-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-headers-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-utils-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nscd-2.5-107.el5_9.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-utils / etc");
}
