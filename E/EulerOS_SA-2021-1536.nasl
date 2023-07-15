#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147038);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id(
    "CVE-2019-17006",
    "CVE-2020-12399",
    "CVE-2020-12400",
    "CVE-2020-12401",
    "CVE-2020-12402",
    "CVE-2020-12403"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : nss-softokn (EulerOS-SA-2021-1536)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nss-softokn packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in the way CHACHA20-POLY1305 was
    implemented in NSS. When using multi-part Chacha20, it
    could cause out-of-bounds reads. This issue was fixed
    by explicitly disabling multi-part ChaCha20 (which was
    not functioning correctly) and strictly enforcing tag
    length. The highest threat from this vulnerability is
    to confidentiality and system
    availability.(CVE-2020-12403)

  - When converting coordinates from projective to affine,
    the modular inversion was not performed in constant
    time, resulting in a possible timing-based side channel
    attack. This vulnerability affects Firefox < 80 and
    Firefox for Android < 80.CVE-2020-12400)

  - NSS has shown timing differences when performing DSA
    signatures, which was exploitable and could eventually
    leak private keys. This vulnerability affects
    Thunderbird < 68.9.0, Firefox < 77, and Firefox ESR <
    68.9.(CVE-2020-12399)

  - During RSA key generation, bignum implementations used
    a variation of the Binary Extended Euclidean Algorithm
    which entailed significantly input-dependent flow. This
    allowed an attacker able to perform
    electromagnetic-based side channel attacks to record
    traces leading to the recovery of the secret primes.
    *Note:* An unmodified Firefox browser does not generate
    RSA keys in normal operation and is not affected, but
    products built on top of it might. This vulnerability
    affects Firefox < 78.(CVE-2020-12402)

  - During ECDSA signature generation, padding applied in
    the nonce designed to ensure constant-time scalar
    multiplication was removed, resulting in variable-time
    execution dependent on secret data. This vulnerability
    affects Firefox < 80 and Firefox for Android <
    80.(CVE-2020-12401)

  - In Network Security Services (NSS) before 3.46, several
    cryptographic primitives had missing length checks. In
    cases where the application calling the library did not
    perform a sanity check on the inputs it could result in
    a crash due to a buffer overflow.(CVE-2019-17006)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1536
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cde9881d");
  script_set_attribute(attribute:"solution", value:
"Update the affected nss-softokn packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["nss-softokn-3.39.0-2.h6.eulerosv2r8",
        "nss-softokn-freebl-3.39.0-2.h6.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss-softokn");
}
