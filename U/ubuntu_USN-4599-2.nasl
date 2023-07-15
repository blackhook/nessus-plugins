##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4599-2. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141923);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-15254",
    "CVE-2020-15680",
    "CVE-2020-15681",
    "CVE-2020-15682",
    "CVE-2020-15683",
    "CVE-2020-15684",
    "CVE-2020-15969"
  );
  script_xref(name:"USN", value:"4599-2");

  script_name(english:"Ubuntu 16.04 LTS : Firefox vulnerabilities (USN-4599-2)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4599-2 advisory.

  - Crossbeam is a set of tools for concurrent programming. In crossbeam-channel before version 0.4.4, the
    bounded channel incorrectly assumes that `Vec::from_iter` has allocated capacity that same as the number
    of iterator elements. `Vec::from_iter` does not actually guarantee that and may allocate extra memory. The
    destructor of the `bounded` channel reconstructs `Vec` from the raw pointer based on the incorrect assumes
    described above. This is unsound and causing deallocation with the incorrect capacity when
    `Vec::from_iter` has allocated different sizes with the number of iterator elements. This has been fixed
    in crossbeam-channel 0.4.4. (CVE-2020-15254)

  - If a valid external protocol handler was referenced in an image tag, the resulting broken image size could
    be distinguished from a broken image size of a non-existent protocol handler. This allowed an attacker to
    successfully probe whether an external protocol handler was registered. This vulnerability affects Firefox
    < 82. (CVE-2020-15680)

  - When multiple WASM threads had a reference to a module, and were looking up exported functions, one WASM
    thread could have overwritten another's entry in a shared stub table, resulting in a potentially
    exploitable crash. This vulnerability affects Firefox < 82. (CVE-2020-15681)

  - When a link to an external protocol was clicked, a prompt was presented that allowed the user to choose
    what application to open it in. An attacker could induce that prompt to be associated with an origin they
    didn't control, resulting in a spoofing attack. This was fixed by changing external protocol prompts to be
    tab-modal while also ensuring they could not be incorrectly associated with a different origin. This
    vulnerability affects Firefox < 82. (CVE-2020-15682)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 81 and Firefox ESR
    78.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.4,
    Firefox < 82, and Thunderbird < 78.4. (CVE-2020-15683)

  - Mozilla developers reported memory safety bugs present in Firefox 81. Some of these bugs showed evidence
    of memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 82. (CVE-2020-15684)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4599-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15684");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'firefox', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-dev', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-af', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-an', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-as', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-az', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-be', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-br', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-da', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-de', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-el', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-en', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-es', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-et', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-he', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-id', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-is', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-it', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-km', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-my', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-or', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-si', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-te', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-th', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '82.0+build2-0ubuntu0.16.04.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-geckodriver / firefox-locale-af / etc');
}