##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0053. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147281);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id(
    "CVE-2019-11756",
    "CVE-2019-17006",
    "CVE-2019-17023",
    "CVE-2020-12402"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : nss Multiple Vulnerabilities (NS-SA-2021-0053)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has nss packages installed that are affected by multiple
vulnerabilities:

  - Improper refcounting of soft token session objects could cause a use-after-free and crash (likely limited
    to a denial of service). This vulnerability affects Firefox < 71. (CVE-2019-11756)

  - In Network Security Services (NSS) before 3.46, several cryptographic primitives had missing length
    checks. In cases where the application calling the library did not perform a sanity check on the inputs it
    could result in a crash due to a buffer overflow. (CVE-2019-17006)

  - After a HelloRetryRequest has been sent, the client may negotiate a lower protocol that TLS 1.3, resulting
    in an invalid state transition in the TLS State Machine. If the client gets into this state, incoming
    Application Data records will be ignored. This vulnerability affects Firefox < 72. (CVE-2019-17023)

  - During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean
    Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform
    electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes.
    *Note:* An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected,
    but products built on top of it might. This vulnerability affects Firefox < 78. (CVE-2020-12402)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0053");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL nss packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'nss-3.53.1-11.el8_2',
    'nss-debuginfo-3.53.1-11.el8_2',
    'nss-debugsource-3.53.1-11.el8_2',
    'nss-devel-3.53.1-11.el8_2',
    'nss-pkcs11-devel-3.53.1-11.el8_2',
    'nss-softokn-3.53.1-11.el8_2',
    'nss-softokn-debuginfo-3.53.1-11.el8_2',
    'nss-softokn-devel-3.53.1-11.el8_2',
    'nss-softokn-freebl-3.53.1-11.el8_2',
    'nss-softokn-freebl-debuginfo-3.53.1-11.el8_2',
    'nss-softokn-freebl-devel-3.53.1-11.el8_2',
    'nss-sysinit-3.53.1-11.el8_2',
    'nss-sysinit-debuginfo-3.53.1-11.el8_2',
    'nss-tools-3.53.1-11.el8_2',
    'nss-tools-debuginfo-3.53.1-11.el8_2',
    'nss-util-3.53.1-11.el8_2',
    'nss-util-debuginfo-3.53.1-11.el8_2',
    'nss-util-devel-3.53.1-11.el8_2'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nss');
}
