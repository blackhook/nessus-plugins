#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1179 and 
# CentOS Errata and Security Advisory 2009:1179 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43772);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0696");
  script_bugtraq_id(35848);
  script_xref(name:"RHSA", value:"2009:1179");

  script_name(english:"CentOS 5 : bind (CESA-2009:1179)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix a security issue are now available for
Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 29th July 2009] The packages in this erratum have been
updated to also correct this issue in the bind-sdb package.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the way BIND handles dynamic update message
packets containing the 'ANY' record type. A remote attacker could use
this flaw to send a specially crafted dynamic update packet that could
cause named to exit with an assertion failure. (CVE-2009-0696)

Note: even if named is not configured for dynamic updates, receiving
such a specially crafted dynamic update packet could still cause named
to exit unexpectedly.

All BIND users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
update, the BIND daemon (named) will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?659ff874"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c9a7a16"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
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
if (rpm_check(release:"CentOS-5", reference:"bind-9.3.4-10.P1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.4-10.P1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.4-10.P1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.4-10.P1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.4-10.P1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.4-10.P1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.4-10.P1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.4-10.P1.el5_3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
}
