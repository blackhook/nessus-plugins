#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5800-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170001);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-44758",
    "CVE-2022-3437",
    "CVE-2022-42898",
    "CVE-2022-44640"
  );
  script_xref(name:"USN", value:"5800-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS : Heimdal vulnerabilities (USN-5800-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5800-1 advisory.

  - Heimdal before 7.7.1 allows attackers to cause a NULL pointer dereference in a SPNEGO acceptor via a
    preferred_mech_type of GSS_C_NO_OID and a nonzero initial_response value to send_accept. (CVE-2021-44758)

  - A heap-based buffer overflow vulnerability was found in Samba within the GSSAPI unwrap_des() and
    unwrap_des3() routines of Heimdal. The DES and Triple-DES decryption routines in the Heimdal GSSAPI
    library allow a length-limited write buffer overflow on malloc() allocated memory when presented with a
    maliciously small packet. This flaw allows a remote user to send specially crafted malicious data to the
    application, possibly resulting in a denial of service (DoS) attack. (CVE-2022-3437)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

  - Heimdal before 7.7.1 allows remote attackers to execute arbitrary code because of an invalid free in the
    ASN.1 codec used by the Key Distribution Center (KDC). (CVE-2022-44640)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5800-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44640");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-clients-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-servers-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libasn1-8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi3-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhcrypto4-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhdb9-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheimbase1-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheimntlm0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhx509-5-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt7-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkafs0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdc2-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-26-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libotp0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroken18-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsl0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwind0-heimdal");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'heimdal-clients', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'heimdal-dev', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'heimdal-kcm', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'heimdal-kdc', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'heimdal-multidev', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'heimdal-servers', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libasn1-8-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libgssapi3-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libhcrypto4-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libhdb9-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libheimbase1-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libheimntlm0-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libhx509-5-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libkadm5clnt7-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libkadm5srv8-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libkafs0-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libkdc2-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libkrb5-26-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libotp0-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libroken18-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libsl0-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '16.04', 'pkgname': 'libwind0-heimdal', 'pkgver': '1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3'},
    {'osver': '18.04', 'pkgname': 'heimdal-clients', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'heimdal-dev', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'heimdal-kcm', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'heimdal-kdc', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'heimdal-multidev', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'heimdal-servers', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libasn1-8-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libgssapi3-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libhcrypto4-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libhdb9-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libheimbase1-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libheimntlm0-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libhx509-5-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libkadm5clnt7-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libkadm5srv8-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libkafs0-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libkdc2-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libkrb5-26-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libotp0-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libroken18-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libsl0-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'libwind0-heimdal', 'pkgver': '7.5.0+dfsg-1ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'heimdal-clients', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'heimdal-dev', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'heimdal-kcm', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'heimdal-kdc', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'heimdal-multidev', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'heimdal-servers', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libasn1-8-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libgssapi3-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libhcrypto4-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libhdb9-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libheimbase1-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libheimntlm0-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libhx509-5-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libkadm5clnt7-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libkadm5srv8-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libkafs0-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libkdc2-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libkrb5-26-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libotp0-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libroken18-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libsl0-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libwind0-heimdal', 'pkgver': '7.7.0+dfsg-1ubuntu1.3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'heimdal-clients / heimdal-dev / heimdal-kcm / heimdal-kdc / etc');
}
