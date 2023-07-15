#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:550 and 
# CentOS Errata and Security Advisory 2005:550 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21839);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-2069");
  script_xref(name:"RHSA", value:"2005:550");

  script_name(english:"CentOS 3 : openssh (CESA-2005:550)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a potential security vulnerability
and various other bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
includes the core files necessary for both the OpenSSH client and
server.

A bug was found in the way the OpenSSH server handled the MaxStartups
and LoginGraceTime configuration variables. A malicious user could
connect to the SSH daemon in such a way that it would prevent
additional logins from occuring until the malicious connections are
closed. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-2069 to this issue.

Additionally, the following issues are resolved with this update :

  - The -q option of the ssh client did not suppress the
    banner message sent by the server, which caused errors
    when used in scripts.

  - The sshd daemon failed to close the client connection if
    multiple X clients were forwarded over the connection
    and the client session exited.

  - The sftp client leaked memory if used for extended
    periods.

  - The sshd daemon called the PAM functions incorrectly if
    the user was unknown on the system.

All users of openssh should upgrade to these updated packages, which
contain backported patches and resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24cdacc0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9da0c1da"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012230.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?237aa73b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
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
if (rpm_check(release:"CentOS-3", reference:"openssh-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-gnome-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-clients-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-server-3.6.1p2-33.30.6")) flag++;


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
