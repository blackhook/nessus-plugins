#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0855 and 
# CentOS Errata and Security Advisory 2008:0855 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43708);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-4752", "CVE-2008-3844");
  script_bugtraq_id(25628, 30794);
  script_xref(name:"RHSA", value:"2008:0855");

  script_name(english:"CentOS 4 / 5 : openssh (CESA-2008:0855)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages are now available for Red Hat Enterprise
Linux 4, Red Hat Enterprise Linux 5, and Red Hat Enterprise Linux 4.5
Extended Update Support.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation.

Last week Red Hat detected an intrusion on certain of its computer
systems and took immediate action. While the investigation into the
intrusion is on-going, our initial focus was to review and test the
distribution channel we use with our customers, Red Hat Network (RHN)
and its associated security measures. Based on these efforts, we
remain highly confident that our systems and processes prevented the
intrusion from compromising RHN or the content distributed via RHN and
accordingly believe that customers who keep their systems updated
using Red Hat Network are not at risk. We are issuing this alert
primarily for those who may obtain Red Hat binary packages via
channels other than those of official Red Hat subscribers.

In connection with the incident, the intruder was able to sign a small
number of OpenSSH packages relating only to Red Hat Enterprise Linux 4
(i386 and x86_64 architectures only) and Red Hat Enterprise Linux 5
(x86_64 architecture only). As a precautionary measure, we are
releasing an updated version of these packages, and have published a
list of the tampered packages and how to detect them at
http://www.redhat.com/security/data/openssh-blacklist.html

To reiterate, our processes and efforts to date indicate that packages
obtained by Red Hat Enterprise Linux subscribers via Red Hat Network
are not at risk.

These packages also fix a low severity flaw in the way ssh handles X11
cookies when creating X11 forwarding connections. When ssh was unable
to create untrusted cookie, ssh used a trusted cookie instead,
possibly allowing the administrative user of a untrusted remote
server, or untrusted application run on the remote server, to gain
unintended access to a users local X server. (CVE-2007-4752)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015193.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12fb949b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7935c468"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015200.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6eaac443"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/23");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-3.9p1-11.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-3.9p1-11.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-gnome-3.9p1-11.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-clients-3.9p1-11.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-server-3.9p1-11.c4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"openssh-4.3p2-26.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-askpass-4.3p2-26.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-clients-4.3p2-26.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-server-4.3p2-26.el5_2.1")) flag++;


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
