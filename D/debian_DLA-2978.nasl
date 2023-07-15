#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2978. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159636);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-1097",
    "CVE-2022-1196",
    "CVE-2022-1197",
    "CVE-2022-24713",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28289"
  );
  script_xref(name:"IAVA", value:"2022-A-0134-S");

  script_name(english:"Debian DLA-2978-1 : thunderbird - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2978 advisory.

  - regex is an implementation of regular expressions for the Rust language. The regex crate features built-in
    mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched
    by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This
    guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in
    the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing,
    and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial
    of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted
    regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is
    include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade
    immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic
    regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability.
    Because of this, it us not recommend to deny known problematic regexes. (CVE-2022-24713)

  - <code>NSSToken</code> objects were referenced via direct points, and could have been accessed in an unsafe
    way on different threads, leading to a use-after-free and potentially exploitable crash. This
    vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox ESR < 91.8. (CVE-2022-1097)

  - After a VR Process is destroyed, a reference to it may have been retained and used, leading to a use-
    after-free and potentially exploitable crash. This vulnerability affects Thunderbird < 91.8 and Firefox
    ESR < 91.8. (CVE-2022-1196)

  - When importing a revoked key that specified key compromise as the revocation reason, Thunderbird did not
    update the existing copy of the key that was not yet revoked, and the existing key was kept as non-
    revoked. Revocation statements that used another revocation reason, or that didn't specify a revocation
    reason, were unaffected. This vulnerability affects Thunderbird < 91.8. (CVE-2022-1197)

  - If a compromised content process sent an unexpected number of WebAuthN Extensions in a Register command to
    the parent process, an out of bounds write would have occurred leading to memory corruption and a
    potentially exploitable crash. This vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox
    ESR < 91.8. (CVE-2022-28281)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/thunderbird");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1097");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28285");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28286");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28289");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/thunderbird");
  script_set_attribute(attribute:"solution", value:
"Upgrade the thunderbird packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24713");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/11");

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

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

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
    {'release': '9.0', 'prefix': 'calendar-google-provider', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-dbg', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-dev', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-all', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ast', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-be', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-bg', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-bn-bd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ca', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-cs', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-da', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-de', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-dsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-el', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-en-gb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-es-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-es-es', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-et', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-eu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-fi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-fr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-fy-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ga-ie', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-gd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-gl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-he', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-hy-am', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-id', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-is', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-it', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ja', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-kab', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ko', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-lt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-nb-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-nn-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pa-in', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pt-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-pt-pt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-rm', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ro', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ru', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-si', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sq', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-sv-se', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-ta-lk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-tr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-uk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-vi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-zh-cn', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'icedove-l10n-zh-tw', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-extension', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ast', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-be', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-bg', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-bn-bd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ca', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-cs', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-cy', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-da', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-de', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-dsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-el', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-en-gb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-es-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-es-es', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-et', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-eu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-fi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-fr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-fy-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ga-ie', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-gd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-gl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-he', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-hy-am', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-id', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-is', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-it', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ja', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-kab', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ko', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-lt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-nb-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-nn-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pa-in', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pt-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-pt-pt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-rm', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ro', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ru', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-si', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sq', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-sv-se', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-ta-lk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-tr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-uk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-vi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-zh-cn', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceowl-l10n-zh-tw', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ast', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-be', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-bg', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-bn-bd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ca', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-cs', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-cy', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-da', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-de', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-dsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-el', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-en-gb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-es-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-es-es', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-et', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-eu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-fi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-fr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-fy-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ga-ie', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-gd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-gl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-he', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-hy-am', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-id', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-is', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-it', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ja', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-kab', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-kk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ko', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-lt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ms', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-nb-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-nn-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pa-in', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pt-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-pt-pt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-rm', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ro', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ru', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-si', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sq', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-sv-se', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-ta-lk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-tr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-uk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-vi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-zh-cn', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'lightning-l10n-zh-tw', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-dbg', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-dev', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-af', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-all', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ast', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-be', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-bg', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-bn-bd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ca', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-cak', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-cs', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-cy', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-da', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-de', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-dsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-el', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-en-ca', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-en-gb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-es-ar', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-es-es', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-et', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-eu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-fi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-fr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-fy-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ga-ie', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-gd', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-gl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-he', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hsb', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hu', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-hy-am', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-id', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-is', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-it', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ja', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ka', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-kab', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-kk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ko', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-lt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-lv', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ms', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-nb-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-nl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-nn-no', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pa-in', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pt-br', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-pt-pt', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-rm', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ro', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ru', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-si', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sl', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sq', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-sv-se', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-ta-lk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-th', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-tr', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-uk', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-uz', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-vi', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-zh-cn', 'reference': '1:91.8.0-1~deb9u1'},
    {'release': '9.0', 'prefix': 'thunderbird-l10n-zh-tw', 'reference': '1:91.8.0-1~deb9u1'}
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
    severity   : SECURITY_WARNING,
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
