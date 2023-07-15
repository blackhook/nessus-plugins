#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1118-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103576);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-7793", "CVE-2017-7805", "CVE-2017-7810", "CVE-2017-7814", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7823", "CVE-2017-7824");

  script_name(english:"Debian DLA-1118-1 : firefox-esr security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been found in the Mozilla Firefox web
browser: Multiple memory safety errors, use-after-frees, buffer
overflows and other implementation errors may lead to the execution of
arbitrary code, denial of service, cross-site scripting or bypass of
the phishing and malware protection feature.

For Debian 7 'Wheezy', these problems have been fixed in version
52.4.0esr-2~deb7u1.

We recommend that you upgrade your firefox-esr packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/firefox-esr"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-dbg");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-el");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ja");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-dbg");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-el");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ja");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"firefox-esr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-dbg", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-dev", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ach", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-af", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-all", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-an", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ar", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-as", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ast", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-az", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-be", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-bg", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-bn-bd", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-bn-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-br", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-bs", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ca", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-cs", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-cy", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-da", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-de", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-dsb", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-el", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-en-gb", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-en-za", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-eo", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-es-ar", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-es-cl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-es-es", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-es-mx", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-et", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-eu", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-fa", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ff", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-fi", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-fr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-fy-nl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ga-ie", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-gd", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-gl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-gn", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-gu-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-he", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-hi-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-hr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-hsb", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-hu", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-hy-am", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-id", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-is", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-it", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ja", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-kk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-km", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-kn", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ko", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-lij", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-lt", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-lv", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-mai", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-mk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ml", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-mr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ms", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-nb-no", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-nl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-nn-no", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-or", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-pa-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-pl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-pt-br", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-pt-pt", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-rm", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ro", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ru", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-si", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-sk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-sl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-son", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-sq", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-sr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-sv-se", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-ta", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-te", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-th", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-tr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-uk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-uz", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-vi", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-xh", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-zh-cn", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"firefox-esr-l10n-zh-tw", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dbg", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dev", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ach", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-af", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-all", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-an", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ar", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-as", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ast", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-az", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-be", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bg", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-bd", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-br", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bs", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ca", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cs", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cy", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-da", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-de", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-dsb", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-el", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-gb", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-za", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eo", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-ar", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-cl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-es", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-mx", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-et", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eu", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fa", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ff", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fi", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fy-nl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ga-ie", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gd", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gn", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gu-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-he", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hi-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hsb", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hu", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hy-am", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-id", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-is", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-it", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ja", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-km", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kn", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ko", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lij", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lt", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lv", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mai", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ml", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ms", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nb-no", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nn-no", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-or", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pa-in", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-br", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-pt", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-rm", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ro", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ru", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-si", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sl", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-son", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sq", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sv-se", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ta", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-te", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-th", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-tr", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-uk", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-uz", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-vi", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-xh", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-cn", reference:"52.4.0esr-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-tw", reference:"52.4.0esr-2~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
