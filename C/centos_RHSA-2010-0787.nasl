#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0787 and 
# CentOS Errata and Security Advisory 2010:0787 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50795);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3847");
  script_bugtraq_id(44154);
  script_xref(name:"RHSA", value:"2010:0787");

  script_name(english:"CentOS 5 : glibc (CESA-2010:0787)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

It was discovered that the glibc dynamic linker/loader did not handle
the $ORIGIN dynamic string token set in the LD_AUDIT environment
variable securely. A local attacker with write access to a file system
containing setuid or setgid binaries could use this flaw to escalate
their privileges. (CVE-2010-3847)

Red Hat would like to thank Tavis Ormandy for reporting this issue.

All users should upgrade to these updated packages, which contain a
backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-October/017099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a326b296"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-October/017100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78dd8315"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc "$ORIGIN" Expansion Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"glibc-2.5-49.el5_5.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-common-2.5-49.el5_5.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-devel-2.5-49.el5_5.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-headers-2.5-49.el5_5.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-utils-2.5-49.el5_5.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nscd-2.5-49.el5_5.6")) flag++;


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
