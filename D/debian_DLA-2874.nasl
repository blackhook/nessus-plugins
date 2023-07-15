#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2874. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156457);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-4126",
    "CVE-2021-38496",
    "CVE-2021-38500",
    "CVE-2021-38502",
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-43528",
    "CVE-2021-43529",
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
    "CVE-2021-43546",
    "CVE-2021-44538"
  );
  script_xref(name:"IAVA", value:"2021-A-0461-S");
  script_xref(name:"IAVA", value:"2021-A-0527-S");
  script_xref(name:"IAVA", value:"2021-A-0603-S");
  script_xref(name:"IAVA", value:"2021-A-0569-S");
  script_xref(name:"IAVA", value:"2021-A-0450-S");

  script_name(english:"Debian DLA-2874-1 : thunderbird - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2874 advisory.

  - During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in
    memory corruption and a potentially exploitable crash. This vulnerability affects Thunderbird < 78.15,
    Thunderbird < 91.2, Firefox ESR < 91.2, Firefox ESR < 78.15, and Firefox < 93. (CVE-2021-38496)

  - Mozilla developers reported memory safety bugs present in Firefox 92 and Firefox ESR 91.1. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.15, Thunderbird < 91.2,
    Firefox ESR < 91.2, Firefox ESR < 78.15, and Firefox < 93. (CVE-2021-38500)

  - Thunderbird ignored the configuration to require STARTTLS security for an SMTP connection. A MITM could
    perform a downgrade attack to intercept transmitted messages, or could take control of the authenticated
    session to execute SMTP commands chosen by the MITM. If an unprotected authentication method was
    configured, the MITM could obtain the authentication credentials, too. This vulnerability affects
    Thunderbird < 91.2. (CVE-2021-38502)

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

  - Thunderbird unexpectedly enabled JavaScript in the composition area. The JavaScript execution context was
    limited to this area and did not receive chrome-level privileges, but could be used as a stepping stone to
    further an attack with other vulnerabilities. This vulnerability affects Thunderbird < 91.4.0.
    (CVE-2021-43528)

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

  - The olm_session_describe function in Matrix libolm before 3.2.7 is vulnerable to a buffer overflow. The
    Olm session object represents a cryptographic channel between two parties. Therefore, its state is
    partially controllable by the remote party of the channel. Attackers can construct a crafted sequence of
    messages to manipulate the state of the receiver's session in such a way that, for some buffer sizes, a
    buffer overflow happens on a call to olm_session_describe. Furthermore, safe buffer sizes were
    undocumented. The overflow content is partially controllable by the attacker and limited to ASCII spaces
    and digits. The known affected products are Element Web And SchildiChat Web. (CVE-2021-44538)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/thunderbird");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2874");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38496");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38500");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38502");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38503");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38504");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38506");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38507");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38508");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38509");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4126");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43528");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43529");
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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44538");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/thunderbird");
  script_set_attribute(attribute:"solution", value:
"Upgrade the thunderbird packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44538");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-38503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:calendar-google-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-extension");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lightning-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'calendar-google-provider', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-dbg', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-dev', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-all', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ast', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-be', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-bg', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-bn-bd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ca', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-cs', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-da', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-de', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-dsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-el', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-en-gb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-es-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-es-es', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-et', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-eu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-fi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-fr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-fy-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ga-ie', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-gd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-gl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-he', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hy-am', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-id', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-is', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-it', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ja', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-kab', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ko', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-lt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-nb-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-nn-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pa-in', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pt-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pt-pt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-rm', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ro', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ru', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-si', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sq', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sv-se', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ta-lk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-tr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-uk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-vi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-zh-cn', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-zh-tw', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-extension', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ast', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-be', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-bg', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-bn-bd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ca', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-cs', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-cy', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-da', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-de', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-dsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-el', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-en-gb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-es-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-es-es', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-et', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-eu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-fi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-fr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-fy-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ga-ie', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-gd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-gl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-he', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hy-am', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-id', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-is', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-it', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ja', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-kab', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ko', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-lt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-nb-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-nn-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pa-in', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pt-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pt-pt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-rm', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ro', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ru', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-si', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sq', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sv-se', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ta-lk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-tr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-uk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-vi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-zh-cn', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-zh-tw', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ast', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-be', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-bg', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-bn-bd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ca', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-cs', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-cy', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-da', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-de', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-dsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-el', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-en-gb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-es-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-es-es', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-et', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-eu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-fi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-fr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-fy-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ga-ie', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-gd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-gl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-he', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hy-am', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-id', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-is', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-it', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ja', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-kab', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-kk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ko', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-lt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ms', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-nb-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-nn-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pa-in', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pt-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pt-pt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-rm', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ro', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ru', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-si', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sq', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sv-se', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ta-lk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-tr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-uk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-vi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-zh-cn', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-zh-tw', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-dbg', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-dev', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-af', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-all', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ast', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-be', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-bg', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-bn-bd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ca', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-cak', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-cs', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-cy', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-da', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-de', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-dsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-el', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-en-ca', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-en-gb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-es-ar', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-es-es', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-et', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-eu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-fi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-fr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-fy-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ga-ie', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-gd', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-gl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-he', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hsb', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hu', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hy-am', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-id', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-is', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-it', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ja', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ka', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-kab', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-kk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ko', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-lt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-lv', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ms', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-nb-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-nl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-nn-no', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pa-in', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pt-br', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pt-pt', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-rm', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ro', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ru', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-si', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sl', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sq', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sv-se', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ta-lk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-th', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-tr', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-uk', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-uz', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-vi', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-zh-cn', 'reference': '1:91.4.1-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-zh-tw', 'reference': '1:91.4.1-1~deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'calendar-google-provider / icedove / icedove-dbg / icedove-dev / etc');
}
