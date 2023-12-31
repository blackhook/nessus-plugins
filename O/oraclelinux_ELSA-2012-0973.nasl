#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0973 and 
# Oracle Linux Security Advisory ELSA-2012-0973 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68563);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"RHSA", value:"2012:0973");

  script_name(english:"Oracle Linux 6 : nspr / nss / nss-util (ELSA-2012-0973)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0973 :

Updated nss, nss-util, and nspr packages that fix one security issue,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

It was found that a Certificate Authority (CA) issued a subordinate CA
certificate to its customer, that could be used to issue certificates
for any name. This update renders the subordinate CA certificate as
untrusted. (BZ#798533)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

The nspr package has been upgraded to upstream version 4.9, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#799193)

The nss-util package has been upgraded to upstream version 3.13.3,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#799192)

The nss package has been upgraded to upstream version 3.13.3, which
provides numerous bug fixes and enhancements over the previous
version. In particular, SSL 2.0 is now disabled by default, support
for SHA-224 has been added, PORT_ErrorToString and PORT_ErrorToName
now return the error message and symbolic name of an NSS error code,
and NSS_GetVersion now returns the NSS version string. (BZ#744070)

These updated nss, nss-util, and nspr packages also provide fixes for
the following bugs :

* A PEM module internal function did not clean up memory when
detecting a non-existent file name. Consequently, memory leaks in
client code occurred. The code has been improved to deallocate such
temporary objects and as a result the reported memory leakage is gone.
(BZ#746632)

* Recent changes to NSS re-introduced a problem where applications
could not use multiple SSL client certificates in the same process.
Therefore, any attempt to run commands that worked with multiple SSL
client certificates, such as the 'yum repolist' command, resulted in a
re-negotiation handshake failure. With this update, a revised patch
correcting this problem has been applied to NSS, and using multiple
SSL client certificates in the same process is now possible again.
(BZ#761086)

* The PEM module did not fully initialize newly constructed objects
with function pointers set to NULL. Consequently, a segmentation
violation in libcurl was sometimes experienced while accessing a
package repository. With this update, the code has been changed to
fully initialize newly allocated objects. As a result, updates can now
be installed without problems. (BZ#768669)

* A lack-of-robustness flaw caused the administration server for Red
Hat Directory Server to terminate unexpectedly because the mod_nss
module made nss calls before initializing nss as per the documented
API. With this update, nss protects itself against being called before
it has been properly initialized by the caller. (BZ#784674)

* Compilation errors occurred with some compilers when compiling code
against NSS 3.13.1. The following error message was displayed :

pkcs11n.h:365:26: warning: '__GNUC_MINOR' is not defined

An upstream patch has been applied to improve the code and the problem
no longer occurs. (BZ#795693)

* Unexpected terminations were reported in the messaging daemon
(qpidd) included in Red Hat Enterprise MRG after a recent update to
nss. This occurred because qpidd made nss calls before initializing
nss. These updated packages prevent qpidd and other affected processes
that call nss without initializing as mandated by the API from
crashing. (BZ#797426)

Users of NSS, NSPR, and nss-util are advised to upgrade to these
updated packages, which fix these issues and add these enhancements.
After installing this update, applications using NSS, NSPR, or
nss-util must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002914.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr, nss and / or nss-util packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"nspr-4.9-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nspr-devel-4.9-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nss-3.13.3-6.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nss-devel-3.13.3-6.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nss-pkcs11-devel-3.13.3-6.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nss-sysinit-3.13.3-6.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nss-tools-3.13.3-6.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-3.13.3-2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-devel-3.13.3-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / etc");
}
