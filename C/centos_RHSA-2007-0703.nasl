#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0703 and 
# CentOS Errata and Security Advisory 2007:0703 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67053);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-5052", "CVE-2007-3102");
  script_bugtraq_id(20245);
  script_xref(name:"RHSA", value:"2007:0703");

  script_name(english:"CentOS 4 : openssh (CESA-2007:0703)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix two security issues and various bugs
are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

A flaw was found in the way the ssh server wrote account names to the
audit subsystem. An attacker could inject strings containing parts of
audit messages which could possibly mislead or confuse audit log
parsing tools. (CVE-2007-3102)

A flaw was found in the way the OpenSSH server processes GSSAPI
authentication requests. When GSSAPI authentication was enabled in
OpenSSH server, a remote attacker may have been able to determine if a
username is valid. (CVE-2006-5052)

The following bugs were also fixed :

* the ssh daemon did not generate audit messages when an ssh session
was closed.

* GSSAPI authentication sometimes failed on clusters using DNS or
load-balancing.

* the sftp client and server leaked small amounts of memory in some
cases.

* the sftp client didn't properly exit and return non-zero status in
batch mode when the destination disk drive was full.

* when restarting the ssh daemon with the initscript, the ssh daemon
was sometimes not restarted successfully because the old running ssh
daemon was not properly killed.

* with challenge/response authentication enabled, the pam sub-process
was not terminated if the user authentication timed out.

All users of openssh should upgrade to these updated packages, which
contain patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-November/014421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf455c0d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-clients-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-server-3.9p1-8.RHEL4.24")) flag++;


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
