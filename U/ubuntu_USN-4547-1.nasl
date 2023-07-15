#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4547-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140920);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2018-7225",
    "CVE-2018-15127",
    "CVE-2018-20019",
    "CVE-2018-20020",
    "CVE-2018-20021",
    "CVE-2018-20022",
    "CVE-2018-20023",
    "CVE-2018-20024",
    "CVE-2018-20748",
    "CVE-2018-20749",
    "CVE-2018-20750",
    "CVE-2019-15681"
  );
  script_bugtraq_id(
    103107,
    106820,
    106821,
    106823,
    106825
  );
  script_xref(name:"USN", value:"4547-1");

  script_name(english:"Ubuntu 18.04 LTS : iTALC vulnerabilities (USN-4547-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4547-1 advisory.

  - An issue was discovered in LibVNCServer through 0.9.11. rfbProcessClientNormalMessage() in rfbserver.c
    does not sanitize msg.cct.length, leading to access to uninitialized and potentially sensitive data or
    possibly unspecified other impact (e.g., an integer overflow) via specially crafted VNC packets.
    (CVE-2018-7225)

  - LibVNC before commit 502821828ed00b4a2c4bef90683d0fd88ce495de contains heap out-of-bound write
    vulnerability in server code of file transfer extension that can result remote code execution
    (CVE-2018-15127)

  - LibVNC before commit a83439b9fbe0f03c48eb94ed05729cb016f8b72f contains multiple heap out-of-bound write
    vulnerabilities in VNC client code that can result remote code execution (CVE-2018-20019)

  - LibVNC before commit 7b1ef0ffc4815cab9a96c7278394152bdc89dc4d contains heap out-of-bound write
    vulnerability inside structure in VNC client code that can result remote code execution (CVE-2018-20020)

  - LibVNC before commit c3115350eb8bb635d0fdb4dbbb0d0541f38ed19c contains a CWE-835: Infinite loop
    vulnerability in VNC client code. Vulnerability allows attacker to consume excessive amount of resources
    like CPU and RAM (CVE-2018-20021)

  - LibVNC before 2f5b2ad1c6c99b1ac6482c95844a84d66bb52838 contains multiple weaknesses CWE-665: Improper
    Initialization vulnerability in VNC client code that allows attacker to read stack memory and can be abuse
    for information disclosure. Combined with another vulnerability, it can be used to leak stack memory
    layout and in bypassing ASLR (CVE-2018-20022)

  - LibVNC before 8b06f835e259652b0ff026898014fc7297ade858 contains CWE-665: Improper Initialization
    vulnerability in VNC Repeater client code that allows attacker to read stack memory and can be abuse for
    information disclosure. Combined with another vulnerability, it can be used to leak stack memory layout
    and in bypassing ASLR (CVE-2018-20023)

  - LibVNC before commit 4a21bbd097ef7c44bb000c3bd0907f96a10e4ce7 contains null pointer dereference in VNC
    client code that can result DoS. (CVE-2018-20024)

  - LibVNC before 0.9.12 contains multiple heap out-of-bounds write vulnerabilities in
    libvncclient/rfbproto.c. The fix for CVE-2018-20019 was incomplete. (CVE-2018-20748)

  - LibVNC before 0.9.12 contains a heap out-of-bounds write vulnerability in libvncserver/rfbserver.c. The
    fix for CVE-2018-15127 was incomplete. (CVE-2018-20749)

  - LibVNC through 0.9.12 contains a heap out-of-bounds write vulnerability in libvncserver/rfbserver.c. The
    fix for CVE-2018-15127 was incomplete. (CVE-2018-20750)

  - LibVNC commit before d01e1bb4246323ba6fcee3b82ef1faa9b1dac82a contains a memory leak (CWE-655) in VNC
    server code, which allow an attacker to read stack memory and can be abused for information disclosure.
    Combined with another vulnerability, it can be used to leak stack memory and bypass ASLR. This attack
    appear to be exploitable via network connectivity. These vulnerabilities have been fixed in commit
    d01e1bb4246323ba6fcee3b82ef1faa9b1dac82a. (CVE-2019-15681)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4547-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected italc-client, italc-master and / or libitalccore packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:italc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:italc-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libitalccore");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'italc-client', 'pkgver': '1:3.0.3+dfsg1-3ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'italc-master', 'pkgver': '1:3.0.3+dfsg1-3ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libitalccore', 'pkgver': '1:3.0.3+dfsg1-3ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'italc-client / italc-master / libitalccore');
}