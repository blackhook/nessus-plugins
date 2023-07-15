#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6010-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174173);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id(
    "CVE-2023-29533",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29537",
    "CVE-2023-29538",
    "CVE-2023-29539",
    "CVE-2023-29540",
    "CVE-2023-29541",
    "CVE-2023-29543",
    "CVE-2023-29544",
    "CVE-2023-29547",
    "CVE-2023-29548",
    "CVE-2023-29549",
    "CVE-2023-29550",
    "CVE-2023-29551"
  );
  script_xref(name:"USN", value:"6010-1");
  script_xref(name:"IAVA", value:"2023-A-0182-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Firefox vulnerabilities (USN-6010-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6010-1 advisory.

  - A website could have obscured the fullscreen notification by using a combination of
    <code>window.open</code>, fullscreen requests, <code>window.name</code> assignments, and
    <code>setInterval</code> calls. This could have led to user confusion and possible spoofing attacks.
    (CVE-2023-29533)

  - Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly
    traced. This resulted in memory corruption and a potentially exploitable crash.  (CVE-2023-29535)

  - An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-
    controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash.
    (CVE-2023-29536)

  - Multiple race conditions in the font initialization could have led to memory corruption and execution of
    attacker-controlled code.  (CVE-2023-29537)

  - Under specific circumstances a WebExtension may have received a <code>jar:file:///</code> URI instead of a
    <code>moz-extension:///</code> URI during a load request. This leaked directory paths on the user's
    machine.  (CVE-2023-29538)

  - When handling the filename directive in the Content-Disposition header, the filename would be truncated if
    the filename contained a NULL character. This could have led to reflected file download attacks
    potentially tricking users to install malware.  (CVE-2023-29539)

  - Using a redirect embedded into <code>sourceMappingUrls</code> could allow for navigation to external
    protocol links in sandboxed iframes without <code>allow-top-navigation-to-custom-protocols</code>.
    (CVE-2023-29540)

  - Firefox did not properly handle downloads of files ending in <code>.desktop</code>, which can be
    interpreted to run attacker-controlled commands.  This bug only affects Firefox for Linux on certain
    Distributions. Other operating systems are unaffected, and Mozilla is unable to enumerate all affected
    Linux Distributions.  (CVE-2023-29541)

  - An attacker could have caused memory corruption and a potentially exploitable use-after-free of a pointer
    in a global object's debugger vector.  (CVE-2023-29543)

  - If multiple instances of resource exhaustion occurred at the incorrect time, the garbage collector could
    have caused memory corruption and a potentially exploitable crash.  (CVE-2023-29544)

  - When a secure cookie existed in the Firefox cookie jar an insecure cookie for the same domain could have
    been created, when it should have silently failed.  This could have led to a desynchronization in expected
    results when reading from the secure cookie.  (CVE-2023-29547)

  - A wrong lowering instruction in the ARM64 Ion compiler resulted in a wrong optimization result.
    (CVE-2023-29548)

  - Under certain circumstances, a call to the <code>bind</code> function may have resulted in the incorrect
    realm.  This may have created a vulnerability relating to JavaScript-implemented sandboxes such as SES.
    (CVE-2023-29549)

  - Mozilla developers Randell Jesup, Andrew Osmond, Sebastian Hengst, Andrew McCreight, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 111 and Firefox ESR 102.9. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2023-29550)

  - Mozilla developers Randell Jesup, Andrew McCreight, Gabriele Svelto, and the Mozilla Fuzzing Team reported
    memory safety bugs present in Firefox 111. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-29551)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6010-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-geckodriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-mozsymbols");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'firefox', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-dev', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-af', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-an', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-as', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-az', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-be', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-br', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-da', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-de', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-el', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-en', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-es', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-et', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-he', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-id', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-is', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-it', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-km', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-my', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-or', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-si', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-te', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-th', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '112.0+build2-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-dev', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-af', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-an', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-as', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-az', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-be', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-br', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-da', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-de', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-el', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-en', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-es', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-et', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-he', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-id', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-is', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-it', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-km', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-my', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-or', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-si', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-te', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-th', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '112.0+build2-0ubuntu0.20.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-geckodriver / firefox-locale-af / etc');
}
