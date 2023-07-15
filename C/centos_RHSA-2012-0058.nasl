#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0058 and 
# CentOS Errata and Security Advisory 2012:0058 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57730);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-5029", "CVE-2011-4609");
  script_bugtraq_id(51439);
  script_xref(name:"RHSA", value:"2012:0058");

  script_name(english:"CentOS 6 : glibc (CESA-2012:0058)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues and three bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library read timezone files. If a
carefully-crafted timezone file was loaded by an application linked
against glibc, it could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2009-5029)

A denial of service flaw was found in the remote procedure call (RPC)
implementation in glibc. A remote attacker able to open a large number
of connections to an RPC service that is using the RPC implementation
from glibc, could use this flaw to make that service use an excessive
amount of CPU time. (CVE-2011-4609)

This update also fixes the following bugs :

* glibc had incorrect information for numeric separators and groupings
for specific French, Spanish, and German locales. Therefore,
applications utilizing glibc's locale support printed numbers with the
wrong separators and groupings when those locales were in use. With
this update, the separator and grouping information has been fixed.
(BZ#754116)

* The RHBA-2011:1179 glibc update introduced a regression, causing
glibc to incorrectly parse groups with more than 126 members,
resulting in applications such as 'id' failing to list all the groups
a particular user was a member of. With this update, group parsing has
been fixed. (BZ#766484)

* glibc incorrectly allocated too much memory due to a race condition
within its own malloc routines. This could cause a multi-threaded
application to allocate more memory than was expected. With this
update, the race condition has been fixed, and malloc's behavior is
now consistent with the documentation regarding the MALLOC_ARENA_TEST
and MALLOC_ARENA_MAX environment variables. (BZ#769594)

Users should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-January/018397.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa3fe85d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-5029");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"glibc-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-common-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-devel-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-headers-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-static-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-utils-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nscd-2.12-1.47.el6_2.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-static / etc");
}
