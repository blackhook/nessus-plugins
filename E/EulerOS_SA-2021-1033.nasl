#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144700);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-1971");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"EulerOS 2.0 SP9 : openssl (EulerOS-SA-2021-1033)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the openssl packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerability :

  - The X.509 GeneralName type is a generic type for
    representing different types of names. One of those
    name types is known as EDIPartyName. OpenSSL provides a
    function GENERAL_NAME_cmp which compares different
    instances of a GENERAL_NAME to see if they are equal or
    not. This function behaves incorrectly when both
    GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer
    dereference and a crash may occur leading to a possible
    denial of service attack. OpenSSL itself uses the
    GENERAL_NAME_cmp function for two purposes: 1)
    Comparing CRL distribution point names between an
    available CRL and a CRL distribution point embedded in
    an X509 certificate 2) When verifying that a timestamp
    response token signer matches the timestamp authority
    name (exposed via the API functions
    TS_RESP_verify_response and TS_RESP_verify_token) If an
    attacker can control both items being compared then
    that attacker could trigger a crash. For example if the
    attacker can trick a client or server into checking a
    malicious certificate against a malicious CRL then this
    may occur. Note that some applications automatically
    download CRLs based on a URL embedded in a certificate.
    This checking happens prior to the signatures on the
    certificate and CRL being verified. OpenSSL's s_server,
    s_client and verify tools have support for the
    '-crl_download' option which implements automatic CRL
    downloading and this attack has been demonstrated to
    work against those tools. Note that an unrelated bug
    means that affected versions of OpenSSL cannot parse or
    construct correct encodings of EDIPARTYNAME. However it
    is possible to construct a malformed EDIPARTYNAME that
    OpenSSL's parser will accept and hence trigger this
    attack. All OpenSSL 1.1.1 and 1.0.2 versions are
    affected by this issue. Other OpenSSL releases are out
    of support and have not been checked. Fixed in OpenSSL
    1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x
    (Affected 1.0.2-1.0.2w).(CVE-2020-1971)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1033
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?524fe2b5");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["openssl-1.1.1f-7.h10.eulerosv2r9",
        "openssl-libs-1.1.1f-7.h10.eulerosv2r9",
        "openssl-perl-1.1.1f-7.h10.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
