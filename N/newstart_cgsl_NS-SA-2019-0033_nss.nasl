#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0033. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127200);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2013-1620",
    "CVE-2013-1739",
    "CVE-2013-1740",
    "CVE-2013-1741",
    "CVE-2013-5605",
    "CVE-2013-5606",
    "CVE-2018-12384"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : nss Multiple Vulnerabilities (NS-SA-2019-0033)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has nss packages installed that are affected by
multiple vulnerabilities:

  - A flaw was found in the way NSS responded to an
    SSLv2-compatible ClientHello with a ServerHello that had
    an all-zero random. A man-in-the-middle attacker could
    use this flaw in a passive replay attack.
    (CVE-2018-12384)

  - The TLS implementation in Mozilla Network Security
    Services (NSS) does not properly consider timing side-
    channel attacks on a noncompliant MAC check operation
    during the processing of malformed CBC padding, which
    allows remote attackers to conduct distinguishing
    attacks and plaintext-recovery attacks via statistical
    analysis of timing data for crafted packets, a related
    issue to CVE-2013-0169. (CVE-2013-1620)

  - Mozilla Network Security Services (NSS) before 3.15.2
    does not ensure that data structures are initialized
    before read operations, which allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via vectors that trigger a decryption
    failure. (CVE-2013-1739)

  - A flaw was found in the way TLS False Start was
    implemented in NSS. An attacker could use this flaw to
    potentially return unencrypted information from the
    server. (CVE-2013-1740)

  - Integer overflow in Mozilla Network Security Services
    (NSS) 3.15 before 3.15.3 allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via a large size value. (CVE-2013-1741)

  - Mozilla Network Security Services (NSS) 3.14 before
    3.14.5 and 3.15 before 3.15.3 allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via invalid handshake packets.
    (CVE-2013-5605)

  - The CERT_VerifyCert function in lib/certhigh/certvfy.c
    in Mozilla Network Security Services (NSS) 3.15 before
    3.15.3 provides an unexpected return value for an
    incompatible key-usage certificate when the
    CERTVerifyLog argument is valid, which might allow
    remote attackers to bypass intended access restrictions
    via a crafted certificate. (CVE-2013-5606)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0033");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL nss packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5605");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-12384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "nss-3.36.0-7.el7_5.cgslv5lite.0.1.gadf9d62",
    "nss-debuginfo-3.36.0-7.el7_5.cgslv5lite.0.1.gadf9d62",
    "nss-devel-3.36.0-7.el7_5.cgslv5lite.0.1.gadf9d62",
    "nss-pkcs11-devel-3.36.0-7.el7_5.cgslv5lite.0.1.gadf9d62",
    "nss-sysinit-3.36.0-7.el7_5.cgslv5lite.0.1.gadf9d62",
    "nss-tools-3.36.0-7.el7_5.cgslv5lite.0.1.gadf9d62"
  ],
  "CGSL MAIN 5.04": [
    "nss-3.36.0-7.el7_5.cgslv5",
    "nss-debuginfo-3.36.0-7.el7_5.cgslv5",
    "nss-devel-3.36.0-7.el7_5.cgslv5",
    "nss-pkcs11-devel-3.36.0-7.el7_5.cgslv5",
    "nss-sysinit-3.36.0-7.el7_5.cgslv5",
    "nss-tools-3.36.0-7.el7_5.cgslv5"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss");
}
