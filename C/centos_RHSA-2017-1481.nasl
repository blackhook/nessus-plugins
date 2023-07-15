#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1481 and 
# CentOS Errata and Security Advisory 2017:1481 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100936);
  script_version("3.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000366");
  script_xref(name:"RHSA", value:"2017:1481");
  script_xref(name:"IAVB", value:"2017-B-0075");

  script_name(english:"CentOS 7 : glibc (CESA-2017:1481) (Stack Clash)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for glibc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
name service cache daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

Security Fix(es) :

* A flaw was found in the way memory was being allocated on the stack
for user space binaries. If heap (or different memory region) and
stack memory regions were adjacent to each other, an attacker could
use this flaw to jump over the stack guard gap, cause controlled
memory corruption on process stack or the adjacent memory region, and
thus increase their privileges on the system. This is glibc-side
mitigation which blocks processing of LD_LIBRARY_PATH for programs
running in secure-execution mode and reduces the number of allocations
performed by the processing of LD_AUDIT, LD_PRELOAD, and
LD_HWCAP_MASK, making successful exploitation of this issue more
difficult. (CVE-2017-1000366)

Red Hat would like to thank Qualys Research Labs for reporting this
issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-June/022463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?584ddf4a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000366");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-2.17-157.el7_3.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-common-2.17-157.el7_3.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-devel-2.17-157.el7_3.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-headers-2.17-157.el7_3.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-static-2.17-157.el7_3.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibc-utils-2.17-157.el7_3.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nscd-2.17-157.el7_3.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-static / etc");
}
