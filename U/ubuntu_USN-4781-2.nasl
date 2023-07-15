#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4781-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170923);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2016-10030", "CVE-2018-10995");
  script_xref(name:"USN", value:"4781-2");

  script_name(english:"Ubuntu 16.04 ESM : Slurm vulnerabilities (USN-4781-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4781-2 advisory.

  - The _prolog_error function in slurmd/req.c in Slurm before 15.08.13, 16.x before 16.05.7, and 17.x before
    17.02.0-pre4 has a vulnerability in how the slurmd daemon informs users of a Prolog failure on a compute
    node. That vulnerability could allow a user to assume control of an arbitrary file on the system. Any
    exploitation of this is dependent on the user being able to cause or anticipate the failure (non-zero
    return code) of a Prolog script that their job would run on. This issue affects all Slurm versions from
    0.6.0 (September 2005) to present. Workarounds to prevent exploitation of this are to either disable your
    Prolog script, or modify it such that it always returns 0 (success) and adjust it to set the node as
    down using scontrol instead of relying on the slurmd to handle that automatically. If you do not have a
    Prolog set you are unaffected by this issue. (CVE-2016-10030)

  - SchedMD Slurm before 17.02.11 and 17.1x.x before 17.11.7 mishandles user names (aka user_name fields) and
    group ids (aka gid fields). (CVE-2018-10995)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4781-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpmi0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurmdb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurmdb-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurmdb26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurmdb29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-client-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-llnl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-llnl-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-llnl-basic-plugins-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-llnl-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-llnl-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-llnl-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-basic-plugins-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurmctld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sview");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libpam-slurm', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libpmi0', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libpmi0-dev', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libslurm-dev', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libslurm-perl', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libslurm29', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libslurmdb-dev', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libslurmdb-perl', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'libslurmdb29', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-client', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-client-emulator', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-llnl', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-llnl-slurmdbd', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-wlm', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-wlm-basic-plugins', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-wlm-basic-plugins-dev', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-wlm-emulator', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurm-wlm-torque', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurmctld', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurmd', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'slurmdbd', 'pkgver': '15.08.7-1ubuntu0.1~esm5'},
    {'osver': '16.04', 'pkgname': 'sview', 'pkgver': '15.08.7-1ubuntu0.1~esm5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpam-slurm / libpmi0 / libpmi0-dev / libslurm-dev / libslurm-perl / etc');
}
