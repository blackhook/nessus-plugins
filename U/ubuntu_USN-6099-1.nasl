#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6099-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176244);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2019-17594",
    "CVE-2019-17595",
    "CVE-2021-39537",
    "CVE-2022-29458",
    "CVE-2023-29491"
  );
  script_xref(name:"USN", value:"6099-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 : ncurses vulnerabilities (USN-6099-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-6099-1 advisory.

  - There is a heap-based buffer over-read in the _nc_find_entry function in tinfo/comp_hash.c in the terminfo
    library in ncurses before 6.1-20191012. (CVE-2019-17594)

  - There is a heap-based buffer over-read in the fmt_entry function in tinfo/comp_hash.c in the terminfo
    library in ncurses before 6.1-20191012. (CVE-2019-17595)

  - An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer
    overflow. (CVE-2021-39537)

  - ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings
    in tinfo/read_entry.c in the terminfo library. (CVE-2022-29458)

  - ncurses before 6.4 20230408, when used by a setuid application, allows local users to trigger security-
    relevant memory corruption via malformed data in a terminfo database file that is found in $HOME/.terminfo
    or reached via the TERMINFO or TERM environment variable. (CVE-2023-29491)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6099-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39537");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncurses-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncursesw5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncursesw5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncursesw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32tinfo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32tinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32tinfo6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ncurses-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ncursesw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64tinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64tinfo6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncurses-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncursesw5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncursesw5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncursesw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtinfo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtinfo6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncursesw5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncursesw5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32tinfo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32tinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-term");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'lib32ncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib32ncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib32ncursesw5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib32ncursesw5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib32tinfo-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib32tinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib64ncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib64ncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'lib64tinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libncursesw5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libncursesw5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libtinfo-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libtinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libx32ncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libx32ncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libx32ncursesw5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libx32ncursesw5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libx32tinfo-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'libx32tinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'ncurses-base', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'ncurses-bin', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'ncurses-examples', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '16.04', 'pkgname': 'ncurses-term', 'pkgver': '6.0+20160213-1ubuntu1+esm3'},
    {'osver': '18.04', 'pkgname': 'lib32ncurses5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib32ncurses5-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib32ncursesw5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib32ncursesw5-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib32tinfo-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib32tinfo5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib64ncurses5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib64ncurses5-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'lib64tinfo5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libncurses5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libncurses5-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libncursesw5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libncursesw5-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libtinfo-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libtinfo5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libx32ncurses5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libx32ncurses5-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libx32ncursesw5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libx32ncursesw5-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libx32tinfo-dev', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libx32tinfo5', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'ncurses-base', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'ncurses-bin', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'ncurses-examples', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '18.04', 'pkgname': 'ncurses-term', 'pkgver': '6.1-1ubuntu1.18.04.1'},
    {'osver': '20.04', 'pkgname': 'lib32ncurses-dev', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'lib32ncurses6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'lib32ncursesw6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'lib32tinfo6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'lib64ncurses-dev', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'lib64ncurses6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'lib64ncursesw6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'lib64tinfo6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libncurses-dev', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libncurses5', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libncurses5-dev', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libncurses6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libncursesw5', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libncursesw5-dev', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libncursesw6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libtinfo-dev', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libtinfo5', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libtinfo6', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'ncurses-base', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'ncurses-bin', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'ncurses-examples', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'ncurses-term', 'pkgver': '6.2-0ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'lib32ncurses-dev', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'lib32ncurses6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'lib32ncursesw6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'lib32tinfo6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'lib64ncurses-dev', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'lib64ncurses6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'lib64ncursesw6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'lib64tinfo6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libncurses-dev', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libncurses5', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libncurses5-dev', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libncurses6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libncursesw5', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libncursesw5-dev', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libncursesw6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtinfo-dev', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtinfo5', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtinfo6', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'ncurses-base', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'ncurses-bin', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'ncurses-examples', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'ncurses-term', 'pkgver': '6.3-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib32ncurses-dev', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib32ncurses6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib32ncursesw6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib32tinfo6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib64ncurses-dev', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib64ncurses6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib64ncursesw6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'lib64tinfo6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libncurses-dev', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libncurses5', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libncurses5-dev', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libncurses6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libncursesw5', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libncursesw5-dev', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libncursesw6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtinfo-dev', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtinfo5', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtinfo6', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'ncurses-base', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'ncurses-bin', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'ncurses-examples', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'ncurses-term', 'pkgver': '6.3+20220423-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib32ncurses-dev', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib32ncurses6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib32ncursesw6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib32tinfo6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib64ncurses-dev', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib64ncurses6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib64ncursesw6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'lib64tinfo6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libncurses-dev', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libncurses5', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libncurses5-dev', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libncurses6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libncursesw5', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libncursesw5-dev', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libncursesw6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtinfo-dev', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtinfo5', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtinfo6', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'ncurses-base', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'ncurses-bin', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'ncurses-examples', 'pkgver': '6.4-2ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'ncurses-term', 'pkgver': '6.4-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lib32ncurses-dev / lib32ncurses5 / lib32ncurses5-dev / etc');
}
