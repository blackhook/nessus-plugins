#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5340-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159137);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2018-9861",
    "CVE-2020-9281",
    "CVE-2021-32808",
    "CVE-2021-32809",
    "CVE-2021-33829",
    "CVE-2021-37695"
  );
  script_xref(name:"USN", value:"5340-1");
  script_xref(name:"IAVA", value:"2021-A-0384-S");
  script_xref(name:"IAVA", value:"2022-A-0032-S");
  script_xref(name:"IAVA", value:"2022-A-0035");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : CKEditor vulnerabilities (USN-5340-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-5340-1 advisory.

  - Cross-site scripting (XSS) vulnerability in the Enhanced Image (aka image2) plugin for CKEditor (in
    versions 4.5.10 through 4.9.1; fixed in 4.9.2), as used in Drupal 8 before 8.4.7 and 8.5.x before 8.5.2
    and other products, allows remote attackers to inject arbitrary web script through a crafted IMG element.
    (CVE-2018-9861)

  - A cross-site scripting (XSS) vulnerability in the HTML Data Processor for CKEditor 4.0 before 4.14 allows
    remote attackers to inject arbitrary web script through a crafted protected comment (with the
    cke_protected syntax). (CVE-2020-9281)

  - ckeditor is an open source WYSIWYG HTML editor with rich content support. A vulnerability has been
    discovered in the clipboard Widget plugin if used alongside the undo feature. The vulnerability allows a
    user to abuse undo functionality using malformed widget HTML, which could result in executing JavaScript
    code. It affects all users using the CKEditor 4 plugins listed above at version >= 4.13.0. The problem has
    been recognized and patched. The fix will be available in version 4.16.2. (CVE-2021-32808)

  - ckeditor is an open source WYSIWYG HTML editor with rich content support. A potential vulnerability has
    been discovered in CKEditor 4 [Clipboard](https://ckeditor.com/cke4/addon/clipboard) package. The
    vulnerability allowed to abuse paste functionality using malformed HTML, which could result in injecting
    arbitrary HTML into the editor. It affects all users using the CKEditor 4 plugins listed above at version
    >= 4.5.2. The problem has been recognized and patched. The fix will be available in version 4.16.2.
    (CVE-2021-32809)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted MFT section is supplied in an NTFS image a heap
    buffer overflow can occur and allow for code execution. (CVE-2021-33289)

  - ckeditor is an open source WYSIWYG HTML editor with rich content support. A potential vulnerability has
    been discovered in CKEditor 4 [Fake Objects](https://ckeditor.com/cke4/addon/fakeobjects) package. The
    vulnerability allowed to inject malformed Fake Objects HTML, which could result in executing JavaScript
    code. It affects all users using the CKEditor 4 plugins listed above at version < 4.16.2. The problem has
    been recognized and patched. The fix will be available in version 4.16.2. (CVE-2021-37695)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5340-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected ckeditor package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33829");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ckeditor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'ckeditor', 'pkgver': '4.5.7+dfsg-2ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'ckeditor', 'pkgver': '4.12.1+dfsg-1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'ckeditor', 'pkgver': '4.16.0+dfsg-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ckeditor');
}
