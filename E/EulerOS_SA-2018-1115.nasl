#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109513);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-3736",
    "CVE-2017-3737",
    "CVE-2017-3738"
  );

  script_name(english:"EulerOS 2.0 SP2 : openssl (EulerOS-SA-2018-1115)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - There is a carry propagating bug in the x86_64
    Montgomery squaring procedure in OpenSSL before 1.0.2m
    and 1.1.0 before 1.1.0g. No EC algorithms are affected.
    Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to
    perform and are not believed likely. Attacks against DH
    are considered just feasible (although very difficult)
    because most of the work necessary to deduce
    information about a private key may be performed
    offline. The amount of resources required for such an
    attack would be very significant and likely only
    accessible to a limited number of attackers. An
    attacker would additionally need online access to an
    unpatched system using the target private key in a
    scenario with persistent DH parameters and a private
    key that is shared between multiple clients. This only
    affects processors that support the BMI1, BMI2 and ADX
    extensions like Intel Broadwell (5th generation) and
    later or AMD Ryzen. (CVE-2017-3736)

  - OpenSSL 1.0.2 (starting from version 1.0.2b) introduced
    an 'error state' mechanism. The intent was that if a
    fatal error occurred during a handshake then OpenSSL
    would move into the error state and would immediately
    fail if you attempted to continue the handshake. This
    works as designed for the explicit handshake functions
    (SSL_do_handshake(), SSL_accept() and SSL_connect()),
    however due to a bug it does not work correctly if
    SSL_read() or SSL_write() is called directly. In that
    scenario, if the handshake fails then a fatal error
    will be returned in the initial function call. If
    SSL_read()/SSL_write() is subsequently called by the
    application for the same SSL object then it will
    succeed and the data is passed without being
    decrypted/encrypted directly from the SSL/TLS record
    layer. In order to exploit this issue an application
    bug would have to be present that resulted in a call to
    SSL_read()/SSL_write() being issued after having
    already received a fatal error. (CVE-2017-3737)

  - There is an overflow bug in the AVX2 Montgomery
    multiplication procedure used in exponentiation with
    1024-bit moduli. No EC algorithms are affected.
    Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to
    perform and are not believed likely. Attacks against
    DH1024 are considered just feasible, because most of
    the work necessary to deduce information about a
    private key may be performed offline. The amount of
    resources required for such an attack would be
    significant. However, for an attack on TLS to be
    meaningful, the server would have to share the DH1024
    private key among multiple clients, which is no longer
    an option since CVE-2016-0701. This only affects
    processors that support the AVX2 but not ADX extensions
    like Intel Haswell (4th generation). (CVE-2017-3738)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b793ef9");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl-1.0.2k-12.h1",
        "openssl-devel-1.0.2k-12.h1",
        "openssl-libs-1.0.2k-12.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
