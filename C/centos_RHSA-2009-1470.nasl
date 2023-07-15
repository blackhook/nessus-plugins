#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1470 and 
# CentOS Errata and Security Advisory 2009:1470 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43797);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2904");
  script_xref(name:"RHSA", value:"2009:1470");

  script_name(english:"CentOS 5 : openssh (CESA-2009:1470)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a security issue are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

A Red Hat specific patch used in the openssh packages as shipped in
Red Hat Enterprise Linux 5.4 (RHSA-2009:1287) loosened certain
ownership requirements for directories used as arguments for the
ChrootDirectory configuration options. A malicious user that also has
or previously had non-chroot shell access to a system could possibly
use this flaw to escalate their privileges and run commands as any
system user. (CVE-2009-2904)

All OpenSSH users are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing this update, the OpenSSH server daemon (sshd) will be
restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8e37fee"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f9e45f0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (rpm_check(release:"CentOS-5", reference:"openssh-4.3p2-36.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-askpass-4.3p2-36.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-clients-4.3p2-36.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-server-4.3p2-36.el5_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-server");
}
