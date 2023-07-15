#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136241);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-1551"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : openssl (EulerOS-SA-2020-1538)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the openssl packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerability :

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
    use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e-dev
    (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u-dev
    (Affected 1.0.2-1.0.2t).(CVE-2019-1551)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1538
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38289154");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["openssl-1.0.2k-16.h10",
        "openssl-devel-1.0.2k-16.h10",
        "openssl-libs-1.0.2k-16.h10"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
