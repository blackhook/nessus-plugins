#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146695);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id(
    "CVE-2015-4171",
    "CVE-2015-8023",
    "CVE-2017-11185",
    "CVE-2017-9022",
    "CVE-2018-10811",
    "CVE-2018-16151",
    "CVE-2018-16152",
    "CVE-2018-17540"
  );
  script_bugtraq_id(
    74933
  );

  script_name(english:"EulerOS 2.0 SP2 : strongimcv (EulerOS-SA-2021-1364)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the strongimcv package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The gmp plugin in strongSwan before 5.7.1 has a Buffer
    Overflow via a crafted certificate.(CVE-2018-17540)

  - In verify_emsa_pkcs1_signature() in
    gmp_rsa_public_key.c in the gmp plugin in strongSwan
    4.x and 5.x before 5.7.0, the RSA implementation based
    on GMP does not reject excess data in the
    digestAlgorithm.parameters field during PKCS#1 v1.5
    signature verification. Consequently, a remote attacker
    can forge signatures when small public exponents are
    being used, which could lead to impersonation when only
    an RSA signature is used for IKEv2 authentication. This
    is a variant of CVE-2006-4790 and
    CVE-2014-1568.(CVE-2018-16152)

  - In verify_emsa_pkcs1_signature() in
    gmp_rsa_public_key.c in the gmp plugin in strongSwan
    4.x and 5.x before 5.7.0, the RSA implementation based
    on GMP does not reject excess data after the encoded
    algorithm OID during PKCS#1 v1.5 signature
    verification. Similar to the flaw in the same version
    of strongSwan regarding digestAlgorithm.parameters, a
    remote attacker can forge signatures when small public
    exponents are being used, which could lead to
    impersonation when only an RSA signature is used for
    IKEv2 authentication.(CVE-2018-16151)

  - strongSwan 5.6.0 and older allows Remote Denial of
    Service because of Missing Initialization of a
    Variable.(CVE-2018-10811)

  - The gmp plugin in strongSwan before 5.5.3 does not
    properly validate RSA public keys before calling
    mpz_powm_sec, which allows remote peers to cause a
    denial of service (floating point exception and process
    crash) via a crafted certificate.(CVE-2017-9022)

  - The gmp plugin in strongSwan before 5.6.0 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and daemon crash) via a crafted RSA
    signature.(CVE-2017-11185)

  - The server implementation of the EAP-MSCHAPv2 protocol
    in the eap-mschapv2 plugin in strongSwan 4.2.12 through
    5.x before 5.3.4 does not properly validate local
    state, which allows remote attackers to bypass
    authentication via an empty Success message in response
    to an initial Challenge message.(CVE-2015-8023)

  - strongSwan 4.3.0 through 5.x before 5.3.2 and
    strongSwan VPN Client before 1.4.6, when using EAP or
    pre-shared keys for authenticating an IKEv2 connection,
    does not enforce server authentication restrictions
    until the entire authentication process is complete,
    which allows remote servers to obtain credentials by
    using a valid certificate and then reading the
    responses.(CVE-2015-4171)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1364
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da7cf8bb");
  script_set_attribute(attribute:"solution", value:
"Update the affected strongimcv packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16152");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:strongimcv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["strongimcv-5.2.0-3.h2"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongimcv");
}
