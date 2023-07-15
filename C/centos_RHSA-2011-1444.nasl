#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1444 and 
# CentOS Errata and Security Advisory 2011:1444 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56784);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_xref(name:"RHSA", value:"2011:1444");

  script_name(english:"CentOS 4 / 5 : nss (CESA-2011:1444)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix one security issue are now available for
Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Network Security Services (NSS) is a set of libraries designed to
support the development of security-enabled client and server
applications.

It was found that the Malaysia-based Digicert Sdn. Bhd. subordinate
Certificate Authority (CA) issued HTTPS certificates with weak keys.
This update renders any HTTPS certificates signed by that CA as
untrusted. This covers all uses of the certificates, including SSL,
S/MIME, and code signing. Note: Digicert Sdn. Bhd. is not the same
company as found at digicert.com. (BZ#751366)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

This update also fixes the following bug on Red Hat Enterprise Linux 
5 :

* When using mod_nss with the Apache HTTP Server, a bug in NSS on Red
Hat Enterprise Linux 5 resulted in file descriptors leaking each time
the Apache HTTP Server was restarted with the 'service httpd reload'
command. This could have prevented the Apache HTTP Server from
functioning properly if all available file descriptors were consumed.
(BZ#743508)

For Red Hat Enterprise Linux 6, these updated packages upgrade NSS to
version 3.12.10. As well, they upgrade NSPR (Netscape Portable
Runtime) to version 4.8.8 and nss-util to version 3.12.10 on Red Hat
Enterprise Linux 6, as required by the NSS update. (BZ#735972,
BZ#736272, BZ#735973)

All NSS users should upgrade to these updated packages, which correct
this issue. After installing the update, applications using NSS must
be restarted for the changes to take effect. In addition, on Red Hat
Enterprise Linux 6, applications using NSPR and nss-util must also be
restarted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcd7e5fd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9475f89"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a2126a7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018186.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?722cbb4b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/14");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-3.12.10-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-3.12.10-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-devel-3.12.10-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-devel-3.12.10-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-tools-3.12.10-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-tools-3.12.10-6.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"nss-3.12.10-7.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.10-7.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.10-7.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.10-7.el5_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-devel / nss-pkcs11-devel / nss-tools");
}
