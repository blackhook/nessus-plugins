##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4623-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142729);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-25654");
  script_xref(name:"USN", value:"4623-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Pacemaker vulnerability (USN-4623-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-4623-1 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4623-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcib27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmcluster-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmcluster29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmcluster4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmcommon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmcommon3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmcommon34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmservice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmservice28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrmservice3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblrmd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblrmd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblrmd28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpacemaker1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpe-rules2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpe-rules26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpe-status10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpe-status28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpengine-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpengine10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstonithd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstonithd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstonithd26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtransitioner2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pacemaker-cli-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pacemaker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pacemaker-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pacemaker-resource-agents");
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
    {'osver': '16.04', 'pkgname': 'libcib-dev', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libcib4', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libcrmcluster-dev', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libcrmcluster4', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libcrmcommon-dev', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libcrmcommon3', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libcrmservice-dev', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libcrmservice3', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'liblrmd-dev', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'liblrmd1', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libpe-rules2', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libpe-status10', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libpengine-dev', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libpengine10', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libstonithd-dev', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libstonithd2', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'libtransitioner2', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'pacemaker', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'pacemaker-cli-utils', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'pacemaker-common', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'pacemaker-remote', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '16.04', 'pkgname': 'pacemaker-resource-agents', 'pkgver': '1.1.14-2ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'libcib-dev', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libcib4', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libcrmcluster-dev', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libcrmcluster4', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libcrmcommon-dev', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libcrmcommon3', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libcrmservice-dev', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libcrmservice3', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'liblrmd-dev', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'liblrmd1', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpe-rules2', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpe-status10', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpengine-dev', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpengine10', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libstonithd-dev', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libstonithd2', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libtransitioner2', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'pacemaker', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'pacemaker-cli-utils', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'pacemaker-common', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'pacemaker-remote', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'pacemaker-resource-agents', 'pkgver': '1.1.18-0ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libcib-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libcib27', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libcrmcluster-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libcrmcluster29', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libcrmcommon-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libcrmcommon34', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libcrmservice-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libcrmservice28', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'liblrmd-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'liblrmd28', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libpacemaker1', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libpe-rules26', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libpe-status28', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libpengine-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libstonithd-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libstonithd26', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'pacemaker', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'pacemaker-cli-utils', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'pacemaker-common', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'pacemaker-dev', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'pacemaker-remote', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'pacemaker-resource-agents', 'pkgver': '2.0.3-3ubuntu4.1'},
    {'osver': '20.10', 'pkgname': 'libcib27', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'libcrmcluster29', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'libcrmcommon34', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'libcrmservice28', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'liblrmd28', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'libpacemaker1', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'libpe-rules26', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'libpe-status28', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'libstonithd26', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'pacemaker', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'pacemaker-cli-utils', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'pacemaker-common', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'pacemaker-dev', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'pacemaker-remote', 'pkgver': '2.0.4-2ubuntu3.1'},
    {'osver': '20.10', 'pkgname': 'pacemaker-resource-agents', 'pkgver': '2.0.4-2ubuntu3.1'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcib-dev / libcib27 / libcib4 / libcrmcluster-dev / libcrmcluster29 / etc');
}