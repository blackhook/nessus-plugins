##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4589-2. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141538);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-15157");
  script_xref(name:"USN", value:"4589-2");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Docker vulnerability (USN-4589-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has a package installed that is affected by a vulnerability as
referenced in the USN-4589-2 advisory.

  - In containerd (an industry-standard container runtime) before version 1.2.14 there is a credential leaking
    vulnerability. If a container image manifest in the OCI Image format or Docker Image V2 Schema 2 format
    includes a URL for the location of a specific image layer (otherwise known as a foreign layer), the
    default containerd resolver will follow that URL to attempt to download it. In v1.2.x but not 1.3.0 or
    later, the default containerd resolver will provide its authentication credentials if the server where the
    URL is located presents an HTTP 401 status code along with registry-specific HTTP headers. If an attacker
    publishes a public image with a manifest that directs one of the layers to be fetched from a web server
    they control and they trick a user or system into pulling the image, they can obtain the credentials used
    for pulling that image. In some cases, this may be the user's username and password for the registry. In
    other cases, this may be the credentials attached to the cloud virtual instance which can grant access to
    other cloud resources in the account. The default containerd resolver is used by the cri-containerd plugin
    (which can be used by Kubernetes), the ctr development tool, and other client programs that have
    explicitly linked against it. This vulnerability has been fixed in containerd 1.2.14. containerd 1.3 and
    later are not affected. If you are using containerd 1.3 or later, you are not affected. If you are using
    cri-containerd in the 1.2 series or prior, you should ensure you only pull images from trusted sources.
    Other container runtimes built on top of containerd but not using the default resolver (such as Docker)
    are not affected. (CVE-2020-15157)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4589-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker.io package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:docker.io");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'docker.io', 'pkgver': '18.09.7-0ubuntu1~16.04.6'},
    {'osver': '18.04', 'pkgname': 'docker.io', 'pkgver': '19.03.6-0ubuntu1~18.04.2'},
    {'osver': '20.04', 'pkgname': 'docker.io', 'pkgver': '19.03.8-0ubuntu1.20.04.1'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker.io');
}