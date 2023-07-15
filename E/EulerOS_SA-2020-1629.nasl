#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137471);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-0735", "CVE-2019-1551", "CVE-2019-1559");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"EulerOS 2.0 SP2 : openssl110f (EulerOS-SA-2020-1629)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl110f packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The OpenSSL ECDSA signature algorithm has been shown to
    be vulnerable to a timing side channel attack. An
    attacker could use variations in the signing algorithm
    to recover the private key. Fixed in OpenSSL 1.1.0j
    (Affected 1.1.0-1.1.0i). Fixed in OpenSSL 1.1.1a
    (Affected 1.1.1).(CVE-2018-0735)

  - If an application encounters a fatal protocol error and
    then calls SSL_shutdown() twice (once to send a
    close_notify, and once to receive one) then OpenSSL can
    respond differently to the calling application if a 0
    byte record is received with invalid padding compared
    to if a 0 byte record is received with an invalid MAC.
    If the application then behaves differently based on
    that in a way that is detectable to the remote peer,
    then this amounts to a padding oracle that could be
    used to decrypt data. In order for this to be
    exploitable 'non-stitched' ciphersuites must be in use.
    Stitched ciphersuites are optimised implementations of
    certain commonly used ciphersuites. Also the
    application must call SSL_shutdown() twice even if a
    protocol error has occurred (applications should not do
    this but some do anyway). Fixed in OpenSSL 1.0.2r
    (Affected 1.0.2-1.0.2q).(CVE-2019-1559)

  - There is an overflow bug in the x64_64 Montgomery
    squaring procedure used in exponentiation with 512-bit
    moduli. No EC algorithms are affected. Analysis
    suggests that attacks against 2-prime RSA1024, 3-prime
    RSA1536, and DSA1024 as a result of this defect would
    be very difficult to perform and are not believed
    likely. Attacks against DH512 are considered just
    feasible. However, for an attack the target would have
    to re-use the DH512 private key, which is not
    recommended anyway. Also applications directly using
    the low level API BN_mod_exp may be affected if they
    use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected
    1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected
    1.0.2-1.0.2t).(CVE-2019-1551)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1629
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e314209d");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl110f packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl110f");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl110f-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl110f-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["openssl110f-1.1.0f-5.h13",
        "openssl110f-devel-1.1.0f-5.h13",
        "openssl110f-libs-1.1.0f-5.h13"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl110f");
}
