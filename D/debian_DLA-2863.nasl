#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2863. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156385);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_cve_id(
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-43534",
    "CVE-2021-43535",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43545",
    "CVE-2021-43546"
  );
  script_xref(name:"IAVA", value:"2021-A-0527-S");
  script_xref(name:"IAVA", value:"2021-A-0569-S");

  script_name(english:"Debian DLA-2863-1 : firefox-esr - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2863 advisory.

  - The iframe sandbox rules were not correctly applied to XSLT stylesheets, allowing an iframe to bypass
    restrictions such as executing scripts or navigating the top-level frame. This vulnerability affects
    Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38503)

  - When interacting with an HTML input element's file picker dialog with webkitdirectory set, a use-after-
    free could have resulted, leading to memory corruption and a potentially exploitable crash. This
    vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38504)

  - Through a series of navigations, Firefox could have entered fullscreen mode without notification or
    warning to the user. This could lead to spoofing attacks on the browser UI including phishing. This
    vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38506)

  - The Opportunistic Encryption feature of HTTP2 (RFC 8164) allows a connection to be transparently upgraded
    to TLS while retaining the visual properties of an HTTP connection, including being same-origin with
    unencrypted connections on port 80. However, if a second encrypted port on the same IP address (e.g. port
    8443) did not opt-in to opportunistic encryption; a network attacker could forward a connection from the
    browser to port 443 to port 8443, causing the browser to treat the content of port 8443 as same-origin
    with HTTP. This was resolved by disabling the Opportunistic Encryption feature, which had low usage. This
    vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38507)

  - By displaying a form validity message in the correct location at the same time as a permission prompt
    (such as for geolocation), the validity message could have obscured the prompt, resulting in the user
    potentially being tricked into granting the permission. This vulnerability affects Firefox < 94,
    Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38508)

  - Due to an unusual sequence of attacker-controlled events, a Javascript alert() dialog with arbitrary
    (although unstyled) contents could be displayed over top an uncontrolled webpage of the attacker's
    choosing. This vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3.
    (CVE-2021-38509)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 93 and Firefox ESR
    91.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 94,
    Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-43534)

  - A use-after-free could have occured when an HTTP2 session object was released on a different thread,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox < 93,
    Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-43535)

  - Under certain circumstances, asynchronous functions could have caused a navigation to fail but expose the
    target URL. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43536)

  - An incorrect type conversion of sizes from 64bit to 32bit integers allowed an attacker to corrupt memory
    leading to a potentially exploitable crash. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR <
    91.4.0, and Firefox < 95. (CVE-2021-43537)

  - By misusing a race in our notification code, an attacker could have forcefully hidden the notification for
    pages that had received full screen and pointer lock access, which could have been used for spoofing
    attacks. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43538)

  - Failure to correctly record the location of live pointers across wasm instance calls resulted in a GC
    occurring within the call not tracing those live pointers. This could have led to a use-after-free causing
    a potentially exploitable crash. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0,
    and Firefox < 95. (CVE-2021-43539)

  - When invoking protocol handlers for external protocols, a supplied parameter URL containing spaces was not
    properly escaped. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43541)

  - Using XMLHttpRequest, an attacker could have identified installed applications by probing error messages
    for loading external protocols. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and
    Firefox < 95. (CVE-2021-43542)

  - Documents loaded with the CSP sandbox directive could have escaped the sandbox's script restriction by
    embedding additional content. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and
    Firefox < 95. (CVE-2021-43543)

  - Using the Location API in a loop could have caused severe application hangs and crashes. This
    vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95. (CVE-2021-43545)

  - It was possible to recreate previous cursor spoofing attacks against users with a zoomed native cursor.
    This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95. (CVE-2021-43546)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/firefox-esr");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38503");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38504");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38506");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38507");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38508");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38509");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43534");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43535");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43536");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43537");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43538");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43539");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43541");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43542");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43543");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43546");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/firefox-esr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the firefox-esr packages.

For Debian 9 stretch, these problems have been fixed in version 91.4.1esr-1~deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ca-valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-mx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gu-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ne-np");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-trs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ca-valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-mx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gu-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ne-np");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-trs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'firefox-esr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-dev', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ach', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-af', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-all', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-an', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ar', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-as', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ast', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-az', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-be', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bg', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bn-bd', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bn-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-br', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bs', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ca', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ca-valencia', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-cak', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-cs', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-cy', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-da', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-de', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-dsb', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-el', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-en-ca', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-en-gb', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-en-za', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-eo', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-ar', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-cl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-es', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-mx', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-et', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-eu', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fa', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ff', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fi', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fy-nl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ga-ie', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gd', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gu-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-he', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hi-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hsb', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hu', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hy-am', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ia', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-id', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-is', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-it', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ja', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ka', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-kab', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-kk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-km', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-kn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ko', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-lij', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-lt', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-lv', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-mai', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-mk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ml', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-mr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ms', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-my', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-nb-no', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ne-np', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-nl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-nn-no', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-oc', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-or', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pa-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pt-br', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pt-pt', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-rm', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ro', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ru', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sco', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-si', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-son', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sq', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sv-se', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-szl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ta', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-te', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-th', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-tl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-tr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-trs', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-uk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ur', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-uz', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-vi', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-xh', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-zh-cn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-zh-tw', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-dev', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ach', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-af', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-all', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-an', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ar', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-as', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ast', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-az', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-be', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bg', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bn-bd', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bn-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-br', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bs', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ca', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ca-valencia', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-cak', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-cs', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-cy', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-da', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-de', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-dsb', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-el', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-en-ca', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-en-gb', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-en-za', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-eo', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-ar', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-cl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-es', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-mx', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-et', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-eu', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fa', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ff', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fi', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fy-nl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ga-ie', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gd', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gu-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-he', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hi-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hsb', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hu', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hy-am', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ia', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-id', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-is', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-it', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ja', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ka', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-kab', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-kk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-km', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-kn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ko', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-lij', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-lt', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-lv', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-mai', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-mk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ml', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-mr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ms', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-my', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-nb-no', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ne-np', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-nl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-nn-no', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-oc', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-or', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pa-in', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pt-br', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pt-pt', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-rm', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ro', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ru', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sco', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-si', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-son', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sq', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sv-se', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-szl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ta', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-te', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-th', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-tl', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-tr', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-trs', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-uk', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ur', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-uz', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-vi', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-xh', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-zh-cn', 'reference': '91.4.1esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-zh-tw', 'reference': '91.4.1esr-1~deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox-esr / firefox-esr-dev / firefox-esr-l10n-ach / etc');
}
