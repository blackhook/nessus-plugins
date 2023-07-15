#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0496 and 
# CentOS Errata and Security Advisory 2011:0496 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53870);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1583", "CVE-2011-3262");
  script_xref(name:"RHSA", value:"2011:0496");

  script_name(english:"CentOS 5 : xen (CESA-2011:0496)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xen packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The xen packages contain administration tools and the xend service for
managing the kernel-xen kernel for virtualization on Red Hat
Enterprise Linux.

It was found that the xc_try_bzip2_decode() and xc_try_lzma_decode()
decode routines did not correctly check for a possible buffer size
overflow in the decoding loop. As well, several integer overflow flaws
and missing error/range checking were found that could lead to an
infinite loop. A privileged guest user could use these flaws to crash
the guest or, possibly, execute arbitrary code in the privileged
management domain (Dom0). (CVE-2011-1583)

All xen users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0933402d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d295ff06"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-120.el5_6.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-120.el5_6.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-120.el5_6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-libs");
}
