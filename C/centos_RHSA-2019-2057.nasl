#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2057 and 
# CentOS Errata and Security Advisory 2019:2057 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128344);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-5741");
  script_xref(name:"RHSA", value:"2019:2057");

  script_name(english:"CentOS 7 : bind (CESA-2019:2057)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for bind is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

The following packages have been upgraded to a later upstream version:
bind (9.11.4). (BZ#1640561)

Security Fix(es) :

* bind: Incorrect documentation of krb5-subdomain and ms-subdomain
update policies (CVE-2018-5741)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005816.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?654818cf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5741");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-chroot-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-devel-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-export-devel-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-export-libs-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-libs-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-libs-lite-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-license-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-lite-devel-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-devel-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-libs-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-utils-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-sdb-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-sdb-chroot-9.11.4-9.P2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-utils-9.11.4-9.P2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-export-devel / etc");
}
