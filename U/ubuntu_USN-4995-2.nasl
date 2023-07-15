#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4995-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151017);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-23961",
    "CVE-2021-23981",
    "CVE-2021-23982",
    "CVE-2021-23984",
    "CVE-2021-23987",
    "CVE-2021-23991",
    "CVE-2021-23992",
    "CVE-2021-23993",
    "CVE-2021-23994",
    "CVE-2021-23995",
    "CVE-2021-23998",
    "CVE-2021-23999",
    "CVE-2021-24002",
    "CVE-2021-29945",
    "CVE-2021-29946",
    "CVE-2021-29948",
    "CVE-2021-29949",
    "CVE-2021-29956",
    "CVE-2021-29957",
    "CVE-2021-29967"
  );
  script_xref(name:"USN", value:"4995-2");
  script_xref(name:"IAVA", value:"2021-A-0051-S");
  script_xref(name:"IAVA", value:"2021-A-0185-S");
  script_xref(name:"IAVA", value:"2021-A-0144-S");
  script_xref(name:"IAVA", value:"2021-A-0163-S");
  script_xref(name:"IAVA", value:"2021-A-0246-S");
  script_xref(name:"IAVA", value:"2021-A-0264-S");

  script_name(english:"Ubuntu 18.04 LTS : Thunderbird vulnerabilities (USN-4995-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4995-2 advisory.

  - Further techniques that built on the slipstream research combined with a malicious webpage could have
    exposed both an internal network's hosts as well as services running on the user's local machine. This
    vulnerability affects Firefox < 85. (CVE-2021-23961)

  - A texture upload of a Pixel Buffer Object could have confused the WebGL code to skip binding the buffer
    used to unpack it, resulting in memory corruption and a potentially exploitable information leak or crash.
    This vulnerability affects Firefox ESR < 78.9, Firefox < 87, and Thunderbird < 78.9. (CVE-2021-23981)

  - Using techniques that built on the slipstream research, a malicious webpage could have scanned both an
    internal network's hosts as well as services running on the user's local machine utilizing WebRTC
    connections. This vulnerability affects Firefox ESR < 78.9, Firefox < 87, and Thunderbird < 78.9.
    (CVE-2021-23982)

  - A malicious extension could have opened a popup window lacking an address bar. The title of the popup
    lacking an address bar should not be fully controllable, but in this situation was. This could have been
    used to spoof a website and attempt to trick the user into providing credentials. This vulnerability
    affects Firefox ESR < 78.9, Firefox < 87, and Thunderbird < 78.9. (CVE-2021-23984)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 86 and Firefox ESR
    78.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.9,
    Firefox < 87, and Thunderbird < 78.9. (CVE-2021-23987)

  - If a Thunderbird user has previously imported Alice's OpenPGP key, and Alice has extended the validity
    period of her key, but Alice's updated key has not yet been imported, an attacker may send an email
    containing a crafted version of Alice's key with an invalid subkey, Thunderbird might subsequently attempt
    to use the invalid subkey, and will fail to send encrypted email to Alice. This vulnerability affects
    Thunderbird < 78.9.1. (CVE-2021-23991)

  - Thunderbird did not check if the user ID associated with an OpenPGP key has a valid self signature. An
    attacker may create a crafted version of an OpenPGP key, by either replacing the original user ID, or by
    adding another user ID. If Thunderbird imports and accepts the crafted key, the Thunderbird user may
    falsely conclude that the false user ID belongs to the correspondent. This vulnerability affects
    Thunderbird < 78.9.1. (CVE-2021-23992)

  - An attacker may perform a DoS attack to prevent a user from sending encrypted email to a correspondent. If
    an attacker creates a crafted OpenPGP key with a subkey that has an invalid self signature, and the
    Thunderbird user imports the crafted key, then Thunderbird may try to use the invalid subkey, but the RNP
    library rejects it from being used, causing encryption to fail. This vulnerability affects Thunderbird <
    78.9.1. (CVE-2021-23993)

  - A WebGL framebuffer was not initialized early enough, resulting in memory corruption and an out of bound
    write. This vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88.
    (CVE-2021-23994)

  - When Responsive Design Mode was enabled, it used references to objects that were previously freed. We
    presume that with enough effort this could have been exploited to run arbitrary code. This vulnerability
    affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-23995)

  - Through complicated navigations with new windows, an HTTP page could have inherited a secure lock icon
    from an HTTPS page. This vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88.
    (CVE-2021-23998)

  - If a Blob URL was loaded through some unusual user interaction, it could have been loaded by the System
    Principal and granted additional privileges that should not be granted to web content. This vulnerability
    affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-23999)

  - When a user clicked on an FTP URL containing encoded newline characters (%0A and %0D), the newlines would
    have been interpreted as such and allowed arbitrary commands to be sent to the FTP server. This
    vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-24002)

  - The WebAssembly JIT could miscalculate the size of a return type, which could lead to a null read and
    result in a crash. *Note: This issue only affected x86-32 platforms. Other platforms are unaffected.*.
    This vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-29945)

  - Ports that were written as an integer overflow above the bounds of a 16-bit integer could have bypassed
    port blocking restrictions when used in the Alt-Svc header. This vulnerability affects Firefox ESR <
    78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-29946)

  - Signatures are written to disk before and read during verification, which might be subject to a race
    condition when a malicious local process or user is replacing the file. This vulnerability affects
    Thunderbird < 78.10. (CVE-2021-29948)

  - When loading the shared library that provides the OTR protocol implementation, Thunderbird will initially
    attempt to open it using a filename that isn't distributed by Thunderbird. If a computer has already been
    infected with a malicious library of the alternative filename, and the malicious library has been copied
    to a directory that is contained in the search path for executable libraries, then Thunderbird will load
    the incorrect library. This vulnerability affects Thunderbird < 78.9.1. (CVE-2021-29949)

  - OpenPGP secret keys that were imported using Thunderbird version 78.8.1 up to version 78.10.1 were stored
    unencrypted on the user's local disk. The master password protection was inactive for those keys. Version
    78.10.2 will restore the protection mechanism for newly imported keys, and will automatically protect keys
    that had been imported using affected Thunderbird versions. This vulnerability affects Thunderbird <
    78.10.2. (CVE-2021-29956)

  - If a MIME encoded email contains an OpenPGP inline signed or encrypted message part, but also contains an
    additional unprotected part, Thunderbird did not indicate that only parts of the message are protected.
    This vulnerability affects Thunderbird < 78.10.2. (CVE-2021-29957)

  - Mozilla developers reported memory safety bugs present in Firefox 88 and Firefox ESR 78.11. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.11, Firefox < 89, and
    Firefox ESR < 78.11. (CVE-2021-29967)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4995-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29967");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-calendar-timezones");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-gdata-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-lightning");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'thunderbird', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:78.11.0+build1-0ubuntu0.18.04.2'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-dev / thunderbird-gnome-support / etc');
}
