#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0697 and 
# CentOS Errata and Security Advisory 2006:0697 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22485);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4924", "CVE-2006-5051", "CVE-2006-5052");
  script_bugtraq_id(20216, 20241);
  script_xref(name:"RHSA", value:"2006:0697");

  script_name(english:"CentOS 3 / 4 : openssh / openssl (CESA-2006:0697)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix two security flaws are now available
for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
package includes the core files necessary for both the OpenSSH client
and server.

Mark Dowd discovered a signal handler race condition in the OpenSSH
sshd server. A remote attacker could possibly leverage this flaw to
cause a denial of service (crash). (CVE-2006-5051) The OpenSSH project
believes the likelihood of successful exploitation leading to
arbitrary code execution appears remote. However, the Red Hat Security
Response Team have not yet been able to verify this claim due to lack
of upstream vulnerability information. We are therefore including a
fix for this flaw and have rated it important security severity in the
event our continued investigation finds this issue to be exploitable.

Tavis Ormandy of the Google Security Team discovered a denial of
service bug in the OpenSSH sshd server. A remote attacker can send a
specially crafted SSH-1 request to the server causing sshd to consume
a large quantity of CPU resources. (CVE-2006-4924)

All users of openssh should upgrade to these updated packages, which
contain backported patches that resolves these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013294.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42ac1cd5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8500f549"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013296.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4eca25d6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da00f6c1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013301.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b734a975"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013304.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e63f62ee"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013305.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59033243"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh and / or openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"openssh-3.6.1p2-33.30.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-3.6.1p2-33.30.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-gnome-3.6.1p2-33.30.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-clients-3.6.1p2-33.30.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-server-3.6.1p2-33.30.12")) flag++;

if (rpm_check(release:"CentOS-4", reference:"openssh-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-clients-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-server-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-devel-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-perl-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl096b-0.9.6b-22.46")) flag++;


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
