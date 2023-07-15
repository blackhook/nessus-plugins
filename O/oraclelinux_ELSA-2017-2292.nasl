#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2292 and 
# Oracle Linux Security Advisory ELSA-2017-2292 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102303);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-7444", "CVE-2017-5334", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337", "CVE-2017-7507", "CVE-2017-7869");
  script_xref(name:"RHSA", value:"2017:2292");

  script_name(english:"Oracle Linux 7 : gnutls (ELSA-2017-2292)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2292 :

An update for gnutls is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The gnutls packages provide the GNU Transport Layer Security (GnuTLS)
library, which implements cryptographic algorithms and protocols such
as SSL, TLS, and DTLS.

The following packages have been upgraded to a later upstream version:
gnutls (3.3.26). (BZ#1378373)

Security Fix(es) :

* A double-free flaw was found in the way GnuTLS parsed certain X.509
certificates with Proxy Certificate Information extension. An attacker
could create a specially crafted certificate which, when processed by
an application compiled against GnuTLS, could cause that application
to crash. (CVE-2017-5334)

* Multiple flaws were found in the way gnutls processed OpenPGP
certificates. An attacker could create specially crafted OpenPGP
certificates which, when parsed by gnutls, would cause it to crash.
(CVE-2017-5335, CVE-2017-5336, CVE-2017-5337, CVE-2017-7869)

* A NULL pointer dereference flaw was found in the way GnuTLS
processed ClientHello messages with status_request extension. A remote
attacker could use this flaw to cause an application compiled with
GnuTLS to crash. (CVE-2017-7507)

* A flaw was found in the way GnuTLS validated certificates using OCSP
responses. This could falsely report a certificate as valid under
certain circumstances. (CVE-2016-7444)

The CVE-2017-7507 issue was discovered by Hubert Kario (Red Hat QE
BaseOS Security team).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007095.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-3.3.26-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-c++-3.3.26-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-dane-3.3.26-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-devel-3.3.26-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-utils-3.3.26-9.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-c++ / gnutls-dane / gnutls-devel / gnutls-utils");
}
