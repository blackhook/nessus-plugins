#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1929 and 
# CentOS Errata and Security Advisory 2018:1929 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110651);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-1064", "CVE-2018-5748");
  script_xref(name:"RHSA", value:"2018:1929");

  script_name(english:"CentOS 6 : libvirt (CESA-2018:1929)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libvirt is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The libvirt library contains a C API for managing and interacting with
the virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

Security Fix(es) :

* libvirt: Resource exhaustion via qemuMonitorIORead() method
(CVE-2018-5748)

* libvirt: Incomplete fix for CVE-2018-5748 triggered by QEMU guest
agent (CVE-2018-1064)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

The CVE-2018-5748 issue was discovered by Daniel P. Berrange (Red Hat)
and Peter Krempa (Red Hat), and the CVE-2018-1064 issue was discovered
by Daniel P. Berrange (Red Hat).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.10 Release Notes and Red Hat Enterprise Linux 6.10
Technical Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-June/005275.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b32bc5f4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1064");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"libvirt-0.10.2-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-client-0.10.2-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-devel-0.10.2-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-python-0.10.2-64.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-devel / libvirt-lock-sanlock / etc");
}
