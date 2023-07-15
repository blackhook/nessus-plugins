#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5724-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167286);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-3266",
    "CVE-2022-39236",
    "CVE-2022-39249",
    "CVE-2022-39250",
    "CVE-2022-39251",
    "CVE-2022-40956",
    "CVE-2022-40957",
    "CVE-2022-40958",
    "CVE-2022-40959",
    "CVE-2022-40960",
    "CVE-2022-40962",
    "CVE-2022-42927",
    "CVE-2022-42928",
    "CVE-2022-42929",
    "CVE-2022-42932"
  );
  script_xref(name:"USN", value:"5724-1");
  script_xref(name:"IAVA", value:"2022-A-0386-S");
  script_xref(name:"IAVA", value:"2022-A-0393-S");
  script_xref(name:"IAVA", value:"2022-A-0444-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Thunderbird vulnerabilities (USN-5724-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5724-1 advisory.

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Starting with version 17.1.0-rc.1,
    improperly formed beacon events can disrupt or impede the matrix-js-sdk from functioning properly,
    potentially impacting the consumer's ability to process data safely. Note that the matrix-js-sdk can
    appear to be operating normally but be excluding or corrupting runtime data presented to the consumer.
    This is patched in matrix-js-sdk v19.7.0. Redacting applicable events, waiting for the sync processor to
    store data, and restarting the client are possible workarounds. Alternatively, redacting the applicable
    events and clearing all storage will fix the further perceived issues. Downgrading to an unaffected
    version, noting that such a version may be subject to other vulnerabilities, will additionally resolve the
    issue. (CVE-2022-39236)

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Prior to version 19.7.0, an attacker
    cooperating with a malicious homeserver can construct messages appearing to have come from another person.
    Such messages will be marked with a grey shield on some platforms, but this may be missing in others. This
    attack is possible due to the matrix-js-sdk implementing a too permissive key forwarding strategy on the
    receiving end. Starting with version 19.7.0, the default policy for accepting key forwards has been made
    more strict in the matrix-js-sdk. matrix-js-sdk will now only accept forwarded keys in response to
    previously issued requests and only from own, verified devices. The SDK now sets a `trusted` flag on the
    decrypted message upon decryption, based on whether the key used to decrypt the message was received from
    a trusted source. Clients need to ensure that messages decrypted with a key with `trusted = false` are
    decorated appropriately, for example, by showing a warning for such messages. This attack requires
    coordination between a malicious homeserver and an attacker, and those who trust your homeservers do not
    need a workaround. (CVE-2022-39249)

  - Matrix JavaScript SDK is the Matrix Client-Server software development kit (SDK) for JavaScript. Prior to
    version 19.7.0, an attacker cooperating with a malicious homeserver could interfere with the verification
    flow between two users, injecting its own cross-signing user identity in place of one of the users'
    identities. This would lead to the other device trusting/verifying the user identity under the control of
    the homeserver instead of the intended one. The vulnerability is a bug in the matrix-js-sdk, caused by
    checking and signing user identities and devices in two separate steps, and inadequately fixing the keys
    to be signed between those steps. Even though the attack is partly made possible due to the design
    decision of treating cross-signing user identities as Matrix devices on the server side (with their device
    ID set to the public part of the user identity key), no other examined implementations were vulnerable.
    Starting with version 19.7.0, the matrix-js-sdk has been modified to double check that the key signed is
    the one that was verified instead of just referencing the key by ID. An additional check has been made to
    report an error when one of the device ID matches a cross-signing key. As this attack requires
    coordination between a malicious homeserver and an attacker, those who trust their homeservers do not need
    a particular workaround. (CVE-2022-39250)

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Prior to version 19.7.0, an attacker
    cooperating with a malicious homeserver can construct messages that legitimately appear to have come from
    another person, without any indication such as a grey shield. Additionally, a sophisticated attacker
    cooperating with a malicious homeserver could employ this vulnerability to perform a targeted attack in
    order to send fake to-device messages appearing to originate from another user. This can allow, for
    example, to inject the key backup secret during a self-verification, to make a targeted device start using
    a malicious key backup spoofed by the homeserver. These attacks are possible due to a protocol confusion
    vulnerability that accepts to-device messages encrypted with Megolm instead of Olm. Starting with version
    19.7.0, matrix-js-sdk has been modified to only accept Olm-encrypted to-device messages. Out of caution,
    several other checks have been audited or added. This attack requires coordination between a malicious
    home server and an attacker, so those who trust their home servers do not need a workaround.
    (CVE-2022-39251)

  - An out-of-bounds read can occur when decoding H264 video. This results in a potentially exploitable crash.
    (CVE-2022-3266)

  - When injecting an HTML base element, some requests would ignore the CSP's base-uri settings and accept the
    injected element's base instead.  (CVE-2022-40956)

  - Inconsistent data in instruction and data cache when creating wasm code could lead to a potentially
    exploitable crash. This bug only affects Firefox on ARM64 platforms.  (CVE-2022-40957)

  - By injecting a cookie with certain special characters, an attacker on a shared subdomain which is not a
    secure context could set and thus overwrite cookies from a secure context, leading to session fixation and
    other attacks.  (CVE-2022-40958)

  - During iframe navigation, certain pages did not have their FeaturePolicy fully initialized leading to a
    bypass that leaked device permissions into untrusted subdocuments.  (CVE-2022-40959)

  - Concurrent use of the URL parser with non-UTF-8 data was not thread-safe. This could lead to a use-after-
    free causing a potentially exploitable crash.  (CVE-2022-40960)

  - Mozilla developers Nika Layzell, Timothy Nikkel, Sebastian Hengst, Andreas Pehrson, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 104 and Firefox ESR 102.2. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2022-40962)

  - A same-origin policy violation could have allowed the theft of cross-origin URL entries, leaking the
    result of a redirect, via <code>performance.getEntries()</code>.  (CVE-2022-42927)

  - Certain types of allocations were missing annotations that, if the Garbage Collector was in a specific
    state, could have lead to memory corruption and a potentially exploitable crash.  (CVE-2022-42928)

  - If a website called <code>window.print()</code> in a particular way, it could cause a denial of service of
    the browser, which may persist beyond browser restart depending on the user's session restore settings.
    (CVE-2022-42929)

  - Mozilla developers Ashley Hale and the Mozilla Fuzzing Team reported memory safety bugs present in
    Thunderbird 102.3. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code.  (CVE-2022-42932)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5724-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-lv");
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
    {'osver': '18.04', 'pkgname': 'thunderbird', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.4.2+build2-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.4.2+build2-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.4.2+build2-0ubuntu0.22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-dev / thunderbird-gnome-support / etc');
}
