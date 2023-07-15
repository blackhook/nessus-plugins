##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4891-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148130);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-3449");
  script_xref(name:"USN", value:"4891-1");
  script_xref(name:"IAVA", value:"2021-A-0149-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 : OpenSSL vulnerability (USN-4891-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-4891-1 advisory.

  - An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a
    client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was
    present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL
    pointer dereference will result, leading to a crash and a denial of service attack. A server is only
    vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS
    clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of
    these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in
    OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j). (CVE-2021-3449)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4891-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrypto1.1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'libcrypto1.1-udeb', 'pkgver': '1.1.1-1ubuntu2.1~18.04.9'},
    {'osver': '18.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1-1ubuntu2.1~18.04.9'},
    {'osver': '18.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1-1ubuntu2.1~18.04.9'},
    {'osver': '18.04', 'pkgname': 'libssl1.1-udeb', 'pkgver': '1.1.1-1ubuntu2.1~18.04.9'},
    {'osver': '18.04', 'pkgname': 'openssl', 'pkgver': '1.1.1-1ubuntu2.1~18.04.9'},
    {'osver': '20.04', 'pkgname': 'libcrypto1.1-udeb', 'pkgver': '1.1.1f-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1f-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1f-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libssl1.1-udeb', 'pkgver': '1.1.1f-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'openssl', 'pkgver': '1.1.1f-1ubuntu2.3'},
    {'osver': '20.10', 'pkgname': 'libcrypto1.1-udeb', 'pkgver': '1.1.1f-1ubuntu4.3'},
    {'osver': '20.10', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1f-1ubuntu4.3'},
    {'osver': '20.10', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1f-1ubuntu4.3'},
    {'osver': '20.10', 'pkgname': 'libssl1.1-udeb', 'pkgver': '1.1.1f-1ubuntu4.3'},
    {'osver': '20.10', 'pkgname': 'openssl', 'pkgver': '1.1.1f-1ubuntu4.3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcrypto1.1-udeb / libssl-dev / libssl1.1 / libssl1.1-udeb / openssl');
}
