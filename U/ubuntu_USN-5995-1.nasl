#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5995-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173831);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2022-0413",
    "CVE-2022-1629",
    "CVE-2022-1674",
    "CVE-2022-1720",
    "CVE-2022-1733",
    "CVE-2022-1735",
    "CVE-2022-1785",
    "CVE-2022-1796",
    "CVE-2022-1851",
    "CVE-2022-1898",
    "CVE-2022-1927",
    "CVE-2022-1942",
    "CVE-2022-1968",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-2129",
    "CVE-2022-2175",
    "CVE-2022-2183",
    "CVE-2022-2206",
    "CVE-2022-2304",
    "CVE-2022-2344",
    "CVE-2022-2345",
    "CVE-2022-2571",
    "CVE-2022-2581",
    "CVE-2022-2845",
    "CVE-2022-2849",
    "CVE-2022-2923",
    "CVE-2022-2946",
    "CVE-2022-2980"
  );
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"USN", value:"5995-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Vim vulnerabilities (USN-5995-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5995-1 advisory.

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-0413, CVE-2022-1898, CVE-2022-1968)

  - Buffer Over-read in function find_next_quote in GitHub repository vim/vim prior to 8.2.4925. This
    vulnerabilities are capable of crashing software, Modify Memory, and possible remote execution
    (CVE-2022-1629)

  - NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 in GitHub repository vim/vim
    prior to 8.2.4938. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 allows
    attackers to cause a denial of service (application crash) via a crafted input. (CVE-2022-1674)

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968. (CVE-2022-1733)

  - Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969. (CVE-2022-1735)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977. (CVE-2022-1785)

  - Use After Free in GitHub repository vim/vim prior to 8.2.4979. (CVE-2022-1796)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1851, CVE-2022-2126,
    CVE-2022-2183, CVE-2022-2206)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1927, CVE-2022-2124, CVE-2022-2175)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-1942, CVE-2022-2125)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-2129)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2304)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045. (CVE-2022-2344)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0046. (CVE-2022-2345)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0101. (CVE-2022-2571)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0104. (CVE-2022-2581)

  - Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218. (CVE-2022-2845)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0220. (CVE-2022-2849)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0240. (CVE-2022-2923)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0246. (CVE-2022-2946)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0259. (CVE-2022-2980)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5995-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2345");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-lesstif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-motif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xxd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'osver': '18.04', 'pkgname': 'vim', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-common', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-gnome', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '18.04', 'pkgname': 'xxd', 'pkgver': '2:8.0.1453-1ubuntu1.12'},
    {'osver': '20.04', 'pkgname': 'vim', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-common', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '20.04', 'pkgname': 'xxd', 'pkgver': '2:8.1.2269-1ubuntu5.13'},
    {'osver': '22.04', 'pkgname': 'vim', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-common', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'xxd', 'pkgver': '2:8.2.3995-1ubuntu2.5'},
    {'osver': '22.10', 'pkgname': 'vim', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-athena', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-common', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-gtk3', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-gui-common', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-motif', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-nox', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-runtime', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'vim-tiny', 'pkgver': '2:9.0.0242-1ubuntu1.3'},
    {'osver': '22.10', 'pkgname': 'xxd', 'pkgver': '2:9.0.0242-1ubuntu1.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-gnome / vim-gtk / vim-gtk3 / etc');
}
