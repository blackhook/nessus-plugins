#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3393. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174436);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_cve_id("CVE-2021-22569", "CVE-2021-22570", "CVE-2022-1941");

  script_name(english:"Debian DLA-3393-1 : protobuf - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3393 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/protobuf");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3393");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22569");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22570");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1941");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/protobuf");
  script_set_attribute(attribute:"solution", value:
"Upgrade the protobuf packages.

For Debian 10 buster, these problems have been fixed in version 3.6.1.3-2+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22569");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1941");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprotobuf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprotobuf-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprotobuf-lite17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprotobuf17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprotoc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprotoc17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:protobuf-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-google-protobuf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libprotobuf-dev', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libprotobuf-java', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libprotobuf-lite17', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libprotobuf17', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libprotoc-dev', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libprotoc17', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'protobuf-compiler', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'python-protobuf', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-protobuf', 'reference': '3.6.1.3-2+deb10u1'},
    {'release': '10.0', 'prefix': 'ruby-google-protobuf', 'reference': '3.6.1.3-2+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libprotobuf-dev / libprotobuf-java / libprotobuf-lite17 / etc');
}
