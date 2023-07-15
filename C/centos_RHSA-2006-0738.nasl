#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0738 and 
# CentOS Errata and Security Advisory 2006:0738 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37366);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-5794");
  script_xref(name:"RHSA", value:"2006:0738");

  script_name(english:"CentOS 3 / 4 : openssh (CESA-2006:0738)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix an authentication flaw are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
package includes the core files necessary for both the OpenSSH client
and server.

An authentication flaw was found in OpenSSH's privilege separation
monitor. If it ever becomes possible to alter the behavior of the
unprivileged process when OpenSSH is using privilege separation, an
attacker may then be able to login without possessing proper
credentials. (CVE-2006-5794)

Please note that this flaw by itself poses no direct threat to OpenSSH
users. Without another security flaw that could allow an attacker to
alter the behavior of OpenSSH's unprivileged process, this flaw cannot
be exploited. There are currently no known flaws to exploit this
behavior. However, we have decided to issue this erratum to fix this
flaw to reduce the security impact if an unprivileged process flaw is
ever found.

Users of openssh should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013400.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?951b9942"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04866605"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7111e9ab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cb246f0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4d657f7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18971c81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"openssh-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-gnome-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-clients-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-server-3.6.1p2-33.30.13")) flag++;

if (rpm_check(release:"CentOS-4", reference:"openssh-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-clients-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-server-3.9p1-8.RHEL4.17.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-askpass-gnome / openssh-clients / etc");
}
