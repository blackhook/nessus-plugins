##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4653-2. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145013);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-15257");
  script_xref(name:"USN", value:"4653-2");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : containerd vulnerability (USN-4653-2)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-4653-2 advisory.

  - containerd is an industry-standard container runtime and is available as a daemon for Linux and Windows.
    In containerd before versions 1.3.9 and 1.4.3, the containerd-shim API is improperly exposed to host
    network containers. Access controls for the shims API socket verified that the connecting process had an
    effective UID of 0, but did not otherwise restrict access to the abstract Unix domain socket. This would
    allow malicious containers running in the same network namespace as the shim, with an effective UID of 0
    but otherwise reduced privileges, to cause new processes to be run with elevated privileges. This
    vulnerability has been fixed in containerd 1.3.9 and 1.4.3. Users should update to these versions as soon
    as they are released. It should be noted that containers started with an old version of containerd-shim
    should be stopped and restarted, as running containers will continue to be vulnerable even after an
    upgrade. If you are not providing the ability for untrusted users to start containers in the same network
    namespace as the shim (typically the host network namespace, for example with docker run --net=host or
    hostNetwork: true in a Kubernetes pod) and run with an effective UID of 0, you are not vulnerable to this
    issue. If you are running containers with a vulnerable configuration, you can deny access to all abstract
    sockets with AppArmor by adding a line similar to deny unix addr=@**, to your policy. It is best practice
    to run containers with a reduced set of privileges, with a non-zero UID, and with isolated namespaces. The
    containerd maintainers strongly advise against sharing namespaces with the host. Reducing the set of
    isolation mechanisms used for a container necessarily increases that container's privilege, regardless of
    what container runtime is used for running that container. (CVE-2020-15257)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4653-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected containerd and / or golang-github-containerd-containerd-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-github-containerd-containerd-dev");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'containerd', 'pkgver': '1.2.6-0ubuntu1~16.04.6'},
    {'osver': '18.04', 'pkgname': 'containerd', 'pkgver': '1.3.3-0ubuntu1~18.04.4'},
    {'osver': '20.04', 'pkgname': 'containerd', 'pkgver': '1.3.3-0ubuntu2.2'},
    {'osver': '20.10', 'pkgname': 'containerd', 'pkgver': '1.3.7-0ubuntu3.2'},
    {'osver': '20.10', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.3.7-0ubuntu3.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd / golang-github-containerd-containerd-dev');
}