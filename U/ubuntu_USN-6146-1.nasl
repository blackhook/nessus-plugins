#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6146-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176981);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id(
    "CVE-2021-31439",
    "CVE-2022-0194",
    "CVE-2022-23121",
    "CVE-2022-23122",
    "CVE-2022-23123",
    "CVE-2022-23124",
    "CVE-2022-23125",
    "CVE-2022-43634",
    "CVE-2022-45188"
  );
  script_xref(name:"USN", value:"6146-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS : Netatalk vulnerabilities (USN-6146-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS host has a package installed that is affected by
multiple vulnerabilities as referenced in the USN-6146-1 advisory.

  - This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations
    of Synology DiskStation Manager. Authentication is not required to exploit this vulnerablity. The specific
    flaw exists within the processing of DSI structures in Netatalk. The issue results from the lack of proper
    validation of the length of user-supplied data prior to copying it to a heap-based buffer. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-12326.
    (CVE-2021-31439)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the ad_addcomment function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-15876. (CVE-2022-0194)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the parse_entries function. The issue results from the lack of proper error handling when parsing
    AppleDouble entries. An attacker can leverage this vulnerability to execute code in the context of root.
    Was ZDI-CAN-15819. (CVE-2022-23121)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the setfilparams function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-15837. (CVE-2022-23122)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the getdirparams method. The issue results from the lack of proper validation of user-supplied data, which
    can result in a read past the end of an allocated buffer. An attacker can leverage this in conjunction
    with other vulnerabilities to execute arbitrary code in the context of root. Was ZDI-CAN-15830.
    (CVE-2022-23123)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the get_finderinfo method. The issue results from the lack of proper validation of user-supplied data,
    which can result in a read past the end of an allocated buffer. An attacker can leverage this in
    conjunction with other vulnerabilities to execute arbitrary code in the context of root. Was ZDI-
    CAN-15870. (CVE-2022-23124)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the copyapplfile function. When parsing the len element, the process does not properly validate the length
    of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage
    this vulnerability to execute code in the context of root. Was ZDI-CAN-15869. (CVE-2022-23125)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the dsi_writeinit function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length heap-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-17646. (CVE-2022-43634)

  - Netatalk through 3.1.13 has an afp_getappl heap-based buffer overflow resulting in code execution via a
    crafted .appl file. This provides remote root access on some platforms such as FreeBSD (used for TrueNAS).
    (CVE-2022-45188)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6146-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected netatalk package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31439");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43634");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netatalk");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'netatalk', 'pkgver': '2.2.5-1ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'netatalk', 'pkgver': '2.2.6-1ubuntu0.18.04.2+esm1'},
    {'osver': '20.04', 'pkgname': 'netatalk', 'pkgver': '3.1.12~ds-4ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'netatalk', 'pkgver': '3.1.12~ds-9ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'netatalk', 'pkgver': '3.1.13~ds-2ubuntu0.22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'netatalk');
}
