##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4635-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142967);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-28196");
  script_xref(name:"USN", value:"4635-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Kerberos vulnerability (USN-4635-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-4635-1 advisory.

  - MIT Kerberos 5 (aka krb5) before 1.17.2 and 1.18.x before 1.18.3 allows unbounded recursion via an
    ASN.1-encoded Kerberos message because the lib/krb5/asn.1/asn1_encode.c support for BER indefinite lengths
    lacks a recursion limit. (CVE-2020-28196)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4635-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-gss-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-k5tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kpropd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-locales', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-otp', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'krb5-user', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkadm5clnt-mit9', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkadm5srv-mit9', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkdb5-8', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkrad0', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '16.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.13.2+dfsg-5ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-locales', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-otp', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'krb5-user', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkadm5clnt-mit11', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkadm5srv-mit11', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkdb5-9', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkrad0', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.16-2ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-locales', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-otp', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'krb5-user', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkadm5clnt-mit11', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkadm5srv-mit11', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkdb5-9', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkrad0', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.17-6ubuntu4.1'},
    {'osver': '20.10', 'pkgname': 'krb5-admin-server', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-k5tls', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-kdc', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-kpropd', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-locales', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-multidev', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-otp', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-pkinit', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'krb5-user', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libgssrpc4', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libk5crypto3', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkadm5clnt-mit11', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkadm5srv-mit11', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkdb5-9', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkrad-dev', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkrad0', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkrb5-3', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkrb5-dev', 'pkgver': '1.17-10ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libkrb5support0', 'pkgver': '1.17-10ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-admin-server / krb5-gss-samples / krb5-k5tls / krb5-kdc / etc');
}