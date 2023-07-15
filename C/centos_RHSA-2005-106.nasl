#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:106 and 
# CentOS Errata and Security Advisory 2005:106 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21798);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0175");
  script_xref(name:"RHSA", value:"2005:106");

  script_name(english:"CentOS 3 : openssh (CESA-2005:106)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a potential security vulnerability
and various other bugs are now available for Red Hat Enterprise Linux
3.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. SSH
replaces rlogin and rsh, and provides secure encrypted communications
between two untrusted hosts over an insecure network. X11 connections
and arbitrary TCP/IP ports can also be forwarded over a secure
channel. Public key authentication can be used for 'passwordless'
access to servers.

The scp protocol allows a server to instruct a client to write to
arbitrary files outside of the current directory. This could
potentially cause a security issue if a user uses scp to copy files
from a malicious server. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0175 to this
issue.

These updated packages also correct the following bugs :

On systems where direct ssh access for the root user was disabled by
configuration (setting 'PermitRootLogin no'), attempts to guess the
root password could be judged as sucessful or unsucessful by observing
a delay.

On systems where the privilege separation feature was turned on, the
user resource limits were not correctly set if the configuration
specified to raise them above the defaults. It was also not possible
to change an expired password.

Users of openssh should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011674.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f0994a3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?276ff729"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31d09e57"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91fa8084"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65d01a5f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"openssh-3.6.1p2-33.30.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-3.6.1p2-33.30.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-gnome-3.6.1p2-33.30.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-clients-3.6.1p2-33.30.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-server-3.6.1p2-33.30.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-askpass-gnome / openssh-clients / etc");
}
