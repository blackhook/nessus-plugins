#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0684 and 
# Oracle Linux Security Advisory ELSA-2016-0684 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90745);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-1978", "CVE-2016-1979");
  script_xref(name:"RHSA", value:"2016:0684");

  script_name(english:"Oracle Linux 5 : nspr / nss (ELSA-2016-0684)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0684 :

An update for nss and nspr is now available for Red Hat Enterprise
Linux 5.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

The following packages have been upgraded to a newer upstream version:
nss 3.21.0, nspr 4.11.0. (BZ#1297944, BZ#1297943)

Security Fix(es) :

* A use-after-free flaw was found in the way NSS handled DHE
(Diffie-Hellman key exchange) and ECDHE (Elliptic Curve Diffie-Hellman
key exchange) handshake messages. A remote attacker could send a
specially crafted handshake message that, when parsed by an
application linked against NSS, would cause that application to crash
or, under certain special conditions, execute arbitrary code using the
permissions of the user running the application. (CVE-2016-1978)

* A use-after-free flaw was found in the way NSS processed certain DER
(Distinguished Encoding Rules) encoded cryptographic keys. An attacker
could use this flaw to create a specially crafted DER encoded
certificate which, when parsed by an application compiled against the
NSS library, could cause that application to crash, or execute
arbitrary code using the permissions of the user running the
application. (CVE-2016-1979)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Eric Rescorla as the original reporter
of CVE-2016-1978; and Tim Taubert as the original reporter of
CVE-2016-1979."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-April/005963.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"nspr-4.11.0-1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-devel-4.11.0-1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-3.21.0-6.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.21.0-6.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.21.0-6.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.21.0-6.el5_11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / nss-tools");
}
