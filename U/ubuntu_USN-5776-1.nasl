#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5776-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168653);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-23471",
    "CVE-2022-24769",
    "CVE-2022-24778",
    "CVE-2022-31030"
  );
  script_xref(name:"USN", value:"5776-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : containerd vulnerabilities (USN-5776-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5776-1 advisory.

  - containerd is an open source container runtime. A bug was found in containerd's CRI implementation where a
    user can exhaust memory on the host. In the CRI stream server, a goroutine is launched to handle terminal
    resize events if a TTY is requested. If the user's process fails to launch due to, for example, a faulty
    command, the goroutine will be stuck waiting to send without a receiver, resulting in a memory leak.
    Kubernetes and crictl can both be configured to use containerd's CRI implementation and the stream server
    is used for handling container IO. This bug has been fixed in containerd 1.6.12 and 1.5.16. Users should
    update to these versions to resolve the issue. Users unable to upgrade should ensure that only trusted
    images and commands are used and that only trusted users have permissions to execute commands in running
    containers. (CVE-2022-23471)

  - Moby is an open-source project created by Docker to enable and accelerate software containerization. A bug
    was found in Moby (Docker Engine) prior to version 20.10.14 where containers were incorrectly started with
    non-empty inheritable Linux process capabilities, creating an atypical Linux environment and enabling
    programs with inheritable file capabilities to elevate those capabilities to the permitted set during
    `execve(2)`. Normally, when executable programs have specified permitted file capabilities, otherwise
    unprivileged users and processes can execute those programs and gain the specified file capabilities up to
    the bounding set. Due to this bug, containers which included executable programs with inheritable file
    capabilities allowed otherwise unprivileged users and processes to additionally gain these inheritable
    file capabilities up to the container's bounding set. Containers which use Linux users and groups to
    perform privilege separation inside the container are most directly impacted. This bug did not affect the
    container security sandbox as the inheritable set never contained more capabilities than were included in
    the container's bounding set. This bug has been fixed in Moby (Docker Engine) 20.10.14. Running containers
    should be stopped, deleted, and recreated for the inheritable capabilities to be reset. This fix changes
    Moby (Docker Engine) behavior such that containers are started with a more typical Linux environment. As a
    workaround, the entry point of a container can be modified to use a utility like `capsh(1)` to drop
    inheritable capabilities prior to the primary process starting. (CVE-2022-24769)

  - The imgcrypt library provides API exensions for containerd to support encrypted container images and
    implements the ctd-decoder command line tool for use by containerd to decrypt encrypted container images.
    The imgcrypt function `CheckAuthorization` is supposed to check whether the current used is authorized to
    access an encrypted image and prevent the user from running an image that another user previously
    decrypted on the same system. In versions prior to 1.1.4, a failure occurs when an image with a
    ManifestList is used and the architecture of the local host is not the first one in the ManifestList. Only
    the first architecture in the list was tested, which may not have its layers available locally since it
    could not be run on the host architecture. Therefore, the verdict on unavailable layers was that the image
    could be run anticipating that image run failure would occur later due to the layers not being available.
    However, this verdict to allow the image to run enabled other architectures in the ManifestList to run an
    image without providing keys if that image had previously been decrypted. A patch has been applied to
    imgcrypt 1.1.4. Workarounds may include usage of different namespaces for each remote user.
    (CVE-2022-24778)

  - containerd is an open source container runtime. A bug was found in the containerd's CRI implementation
    where programs inside a container can cause the containerd daemon to consume memory without bound during
    invocation of the `ExecSync` API. This can cause containerd to consume all available memory on the
    computer, denying service to other legitimate workloads. Kubernetes and crictl can both be configured to
    use containerd's CRI implementation; `ExecSync` may be used when running probes or when executing
    processes via an exec facility. This bug has been fixed in containerd 1.6.6 and 1.5.13. Users should
    update to these versions to resolve the issue. Users unable to upgrade should ensure that only trusted
    images and commands are used. (CVE-2022-31030)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5776-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected containerd and / or golang-github-containerd-containerd-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-github-containerd-containerd-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'containerd', 'pkgver': '1.5.9-0ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.5.9-0ubuntu1~18.04.2'},
    {'osver': '20.04', 'pkgname': 'containerd', 'pkgver': '1.5.9-0ubuntu1~20.04.6'},
    {'osver': '20.04', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.5.9-0ubuntu1~20.04.6'},
    {'osver': '22.04', 'pkgname': 'containerd', 'pkgver': '1.5.9-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.5.9-0ubuntu3.1'},
    {'osver': '22.10', 'pkgname': 'containerd', 'pkgver': '1.6.4-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.6.4-0ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd / golang-github-containerd-containerd-dev');
}
