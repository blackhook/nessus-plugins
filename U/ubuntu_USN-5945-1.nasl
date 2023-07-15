#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5945-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172495);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2021-22569", "CVE-2021-22570", "CVE-2022-1941");
  script_xref(name:"USN", value:"5945-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Protocol Buffers vulnerabilities (USN-5945-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5945-1 advisory.

  - An issue in protobuf-java allowed the interleaving of com.google.protobuf.UnknownFieldSet fields in such a
    way that would be processed out of order. A small malicious payload can occupy the parser for several
    minutes by creating large numbers of short-lived objects that cause frequent, repeated pauses. We
    recommend upgrading libraries beyond the vulnerable versions. (CVE-2021-22569)

  - Nullptr dereference when a null char is present in a proto symbol. The symbol is parsed incorrectly,
    leading to an unchecked call into the proto file's name during generation of the resulting error message.
    Since the symbol is incorrectly parsed, the file is nullptr. We recommend upgrading to version 3.15.0 or
    greater. (CVE-2021-22570)

  - A parsing vulnerability for the MessageSet type in the ProtocolBuffers versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 3.21.5 for protobuf-cpp, and versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 4.21.5 for protobuf-python can lead to out of memory failures.
    A specially crafted message with multiple key-value per elements creates parsing issues, and can lead to a
    Denial of Service against services receiving unsanitized input. We recommend upgrading to versions 3.18.3,
    3.19.5, 3.20.2, 3.21.6 for protobuf-cpp and 3.18.3, 3.19.5, 3.20.2, 4.21.6 for protobuf-python. Versions
    for 3.16 and 3.17 are no longer updated. (CVE-2022-1941)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5945-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22569");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:elpa-protobuf-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-lite10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-lite17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-lite23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-lite8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:protobuf-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby-google-protobuf");
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
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libprotobuf-dev', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libprotobuf-java', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libprotobuf-lite10', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libprotobuf10', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libprotoc-dev', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libprotoc10', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'protobuf-compiler', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'python-protobuf', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'python3-protobuf', 'pkgver': '3.0.0-9.1ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libprotobuf-dev', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'libprotobuf-java', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'libprotobuf-lite17', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'libprotobuf17', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'libprotoc-dev', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'libprotoc17', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'protobuf-compiler', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'python-protobuf', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'python3-protobuf', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '20.04', 'pkgname': 'ruby-google-protobuf', 'pkgver': '3.6.1.3-2ubuntu5.2'},
    {'osver': '22.04', 'pkgname': 'elpa-protobuf-mode', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libprotobuf-dev', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libprotobuf-java', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libprotobuf-lite23', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libprotobuf23', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libprotoc-dev', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libprotoc23', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'protobuf-compiler', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3-protobuf', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.04', 'pkgname': 'ruby-google-protobuf', 'pkgver': '3.12.4-1ubuntu7.22.04.1'},
    {'osver': '22.10', 'pkgname': 'elpa-protobuf-mode', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libprotobuf-dev', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libprotobuf-java', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libprotobuf-lite23', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libprotobuf23', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libprotoc-dev', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libprotoc23', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'protobuf-compiler', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'python3-protobuf', 'pkgver': '3.12.4-1ubuntu7.22.10.1'},
    {'osver': '22.10', 'pkgname': 'ruby-google-protobuf', 'pkgver': '3.12.4-1ubuntu7.22.10.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'elpa-protobuf-mode / libprotobuf-dev / libprotobuf-java / etc');
}
