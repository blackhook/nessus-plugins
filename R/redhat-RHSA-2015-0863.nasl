#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0863. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82984);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2013-7423", "CVE-2015-1781");
  script_bugtraq_id(72844, 74255);
  script_xref(name:"RHSA", value:"2015:0863");

  script_name(english:"RHEL 6 : glibc (RHSA-2015:0863)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated glibc packages that fix two security issues and one bug are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

A buffer overflow flaw was found in the way glibc's gethostbyname_r()
and other related functions computed the size of a buffer when passed
a misaligned buffer as input. An attacker able to make an application
call any of these functions with a misaligned buffer could use this
flaw to crash the application or, potentially, execute arbitrary code
with the permissions of the user running the application.
(CVE-2015-1781)

It was discovered that, under certain circumstances, glibc's
getaddrinfo() function would send DNS queries to random file
descriptors. An attacker could potentially use this flaw to send DNS
queries to unintended recipients, resulting in information disclosure
or data loss due to the application encountering corrupted data.
(CVE-2013-7423)

The CVE-2015-1781 issue was discovered by Arjun Shankar of Red Hat.

This update also fixes the following bug :

* Previously, the nscd daemon did not properly reload modified data
when the user edited monitored nscd configuration files. As a
consequence, nscd returned stale data to system processes. This update
adds a system of inotify-based monitoring and stat-based backup
monitoring for nscd configuration files. As a result, nscd now detects
changes to its configuration files and reloads the data properly,
which prevents it from returning stale data. (BZ#1194149)

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:0863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-7423"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0863";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"glibc-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-common-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-common-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-common-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-common-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-devel-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-headers-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-headers-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-headers-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-static-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-utils-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-utils-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-utils-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nscd-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nscd-2.12-1.149.el6_6.7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nscd-2.12-1.149.el6_6.7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
  }
}
