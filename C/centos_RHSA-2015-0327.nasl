#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0327 and 
# CentOS Errata and Security Advisory 2015:0327 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81889);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-6040", "CVE-2014-8121");
  script_bugtraq_id(73038);
  script_xref(name:"RHSA", value:"2015:0327");

  script_name(english:"CentOS 7 : glibc (CESA-2015:0327)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

An out-of-bounds read flaw was found in the way glibc's iconv()
function converted certain encoded data to UTF-8. An attacker able to
make an application call the iconv() function with a specially crafted
argument could use this flaw to crash that application.
(CVE-2014-6040)

It was found that the files back end of Name Service Switch (NSS) did
not isolate iteration over an entire database from key-based look-up
API calls. An application performing look-ups on a database while
iterating over it could enter an infinite loop, leading to a denial of
service. (CVE-2014-8121)

This update also fixes the following bugs :

* Due to problems with buffer extension and reallocation, the nscd
daemon terminated unexpectedly with a segmentation fault when
processing long netgroup entries. With this update, the handling of
long netgroup entries has been corrected and nscd no longer crashes in
the described scenario. (BZ#1138520)

* If a file opened in append mode was truncated with the ftruncate()
function, a subsequent ftell() call could incorrectly modify the file
offset. This update ensures that ftell() modifies the stream state
only when it is in append mode and the buffer for the stream is not
empty. (BZ#1156331)

* A defect in the C library headers caused builds with older compilers
to generate incorrect code for the btowc() function in the older
compatibility C++ standard library. Applications calling btowc() in
the compatibility C++ standard library became unresponsive. With this
update, the C library headers have been corrected, and the
compatibility C++ standard library shipped with Red Hat Enterprise
Linux has been rebuilt. Applications that rely on the compatibility
C++ standard library no longer hang when calling btowc(). (BZ#1120490)

* Previously, when using netgroups and the nscd daemon was set up to
cache netgroup information, the sudo utility denied access to valid
users. The bug in nscd has been fixed, and sudo now works in netgroups
as expected. (BZ#1080766)

Users of glibc are advised to upgrade to these updated packages, which
fix these issues."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-March/001556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ee84a05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6040");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-2.17-78.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-common-2.17-78.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-devel-2.17-78.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-headers-2.17-78.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-static-2.17-78.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-utils-2.17-78.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nscd-2.17-78.el7")) flag++;


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
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-static / etc");
}
