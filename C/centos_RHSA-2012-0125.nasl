#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0125 and 
# CentOS Errata and Security Advisory 2012:0125 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57923);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0296", "CVE-2010-0830", "CVE-2011-1071", "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1659", "CVE-2011-4609");
  script_bugtraq_id(40063, 46563, 46740, 47370, 50898, 51439);
  script_xref(name:"RHSA", value:"2012:0125");

  script_name(english:"CentOS 4 : glibc (CESA-2012:0125)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix multiple security issues and one bug
are now available for Red Hat Enterprise Linux 4.

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

A flaw was found in the way the ldd utility identified dynamically
linked libraries. If an attacker could trick a user into running ldd
on a malicious binary, it could result in arbitrary code execution
with the privileges of the user running ldd. (CVE-2009-5064)

It was discovered that the glibc addmntent() function, used by various
mount helper utilities, did not sanitize its input properly. A local
attacker could possibly use this flaw to inject malformed lines into
the mtab (mounted file systems table) file via certain setuid mount
helpers, if the attacker were allowed to mount to an arbitrary
directory under their control. (CVE-2010-0296)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library loaded ELF (Executable and Linking
Format) files. If a carefully-crafted ELF file was loaded by an
application linked against glibc, it could cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2010-0830)

It was discovered that the glibc fnmatch() function did not properly
restrict the use of alloca(). If the function was called on
sufficiently large inputs, it could cause an application using
fnmatch() to crash or, possibly, execute arbitrary code with the
privileges of the application. (CVE-2011-1071)

It was found that the glibc addmntent() function, used by various
mount helper utilities, did not handle certain errors correctly when
updating the mtab (mounted file systems table) file. If such utilities
had the setuid bit set, a local attacker could use this flaw to
corrupt the mtab file. (CVE-2011-1089)

It was discovered that the locale command did not produce properly
escaped output as required by the POSIX specification. If an attacker
were able to set the locale environment variables in the environment
of a script that performed shell evaluation on the output of the
locale command, and that script were run with different privileges
than the attacker's, it could execute arbitrary code with the
privileges of the script. (CVE-2011-1095)

An integer overflow flaw was found in the glibc fnmatch() function. If
an attacker supplied a long UTF-8 string to an application linked
against glibc, it could cause the application to crash.
(CVE-2011-1659)

A denial of service flaw was found in the remote procedure call (RPC)
implementation in glibc. A remote attacker able to open a large number
of connections to an RPC service that is using the RPC implementation
from glibc, could use this flaw to make that service use an excessive
amount of CPU time. (CVE-2011-4609)

Red Hat would like to thank the Ubuntu Security Team for reporting
CVE-2010-0830, and Dan Rosenberg for reporting CVE-2011-1089. The
Ubuntu Security Team acknowledges Dan Rosenberg as the original
reporter of CVE-2010-0830.

This update also fixes the following bug :

* When using an nscd package that is a different version than the
glibc package, the nscd service could fail to start. This update makes
the nscd package require a specific glibc version to prevent this
problem. (BZ#657009)

Users should upgrade to these updated packages, which resolve these
issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-February/018427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04137bde"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0296");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nptl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"glibc-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"glibc-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"glibc-common-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"glibc-common-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"glibc-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"glibc-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"glibc-headers-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"glibc-headers-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"glibc-profile-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"glibc-profile-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"glibc-utils-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"glibc-utils-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nptl-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nptl-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nscd-2.3.4-2.57")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nscd-2.3.4-2.57")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-profile / etc");
}
