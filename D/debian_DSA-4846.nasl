#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4846. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146318);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-16044", "CVE-2021-21117", "CVE-2021-21118", "CVE-2021-21119", "CVE-2021-21120", "CVE-2021-21121", "CVE-2021-21122", "CVE-2021-21123", "CVE-2021-21124", "CVE-2021-21125", "CVE-2021-21126", "CVE-2021-21127", "CVE-2021-21128", "CVE-2021-21129", "CVE-2021-21130", "CVE-2021-21131", "CVE-2021-21132", "CVE-2021-21133", "CVE-2021-21134", "CVE-2021-21135", "CVE-2021-21136", "CVE-2021-21137", "CVE-2021-21138", "CVE-2021-21139", "CVE-2021-21140", "CVE-2021-21141", "CVE-2021-21142", "CVE-2021-21143", "CVE-2021-21144", "CVE-2021-21145", "CVE-2021-21146", "CVE-2021-21147");
  script_xref(name:"DSA", value:"4846");

  script_name(english:"Debian DSA-4846-1 : chromium - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the chromium web
browser.

  - CVE-2020-16044
    Ned Williamson discovered a use-after-free issue in the
    WebRTC implementation.

  - CVE-2021-21117
    Rory McNamara discovered a policy enforcement issue in
    Cryptohome.

  - CVE-2021-21118
    Tyler Nighswander discovered a data validation issue in
    the v8 JavaScript library.

  - CVE-2021-21119
    A use-after-free issue was discovered in media handling.

  - CVE-2021-21120
    Nan Wang and Guang Gong discovered a use-after-free
    issue in the WebSQL implementation.

  - CVE-2021-21121
    Leecraso and Guang Gong discovered a use-after-free
    issue in the Omnibox.

  - CVE-2021-21122
    Renata Hodovan discovered a use-after-free issue in
    Blink/WebKit.

  - CVE-2021-21123
    Maciej Pulikowski discovered a data validation issue.

  - CVE-2021-21124
    Chaoyang Ding discovered a use-after-free issue in the
    speech recognizer.

  - CVE-2021-21125
    Ron Masas discovered a policy enforcement issue.

  - CVE-2021-21126
    David Erceg discovered a policy enforcement issue in
    extensions.

  - CVE-2021-21127
    Jasminder Pal Singh discovered a policy enforcement
    issue in extensions.

  - CVE-2021-21128
    Liang Dong discovered a buffer overflow issue in
    Blink/WebKit.

  - CVE-2021-21129
    Maciej Pulikowski discovered a policy enforcement issue.

  - CVE-2021-21130
    Maciej Pulikowski discovered a policy enforcement issue.

  - CVE-2021-21131
    Maciej Pulikowski discovered a policy enforcement issue.

  - CVE-2021-21132
    David Erceg discovered an implementation error in the
    developer tools.

  - CVE-2021-21133
    wester0x01 discovered a policy enforcement issue.

  - CVE-2021-21134
    wester0x01 discovered a user interface error.

  - CVE-2021-21135
    ndevtk discovered an implementation error in the
    Performance API.

  - CVE-2021-21136
    Shiv Sahni, Movnavinothan V, and Imdad Mohammed
    discovered a policy enforcement error.

  - CVE-2021-21137
    bobbybear discovered an implementation error in the
    developer tools.

  - CVE-2021-21138
    Weipeng Jiang discovered a use-after-free issue in the
    developer tools.

  - CVE-2021-21139
    Jun Kokatsu discovered an implementation error in the
    iframe sandbox.

  - CVE-2021-21140
    David Manouchehri discovered uninitialized memory in the
    USB implementation.

  - CVE-2021-21141
    Maciej Pulikowski discovered a policy enforcement error.

  - CVE-2021-21142
    Khalil Zhani discovered a use-after-free issue.

  - CVE-2021-21143
    Allen Parker and Alex Morgan discovered a buffer
    overflow issue in extensions.

  - CVE-2021-21144
    Leecraso and Guang Gong discovered a buffer overflow
    issue.

  - CVE-2021-21145
    A use-after-free issue was discovered.

  - CVE-2021-21146
    Alison Huffman and Choongwoo Han discovered a
    use-after-free issue.

  - CVE-2021-21147
    Roman Starkov discovered an implementation error in the
    skia library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-16044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4846"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the stable distribution (buster), these problems have been fixed
in version 88.0.4324.146-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21117");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"chromium", reference:"88.0.4324.146-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"88.0.4324.146-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"88.0.4324.146-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"88.0.4324.146-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"88.0.4324.146-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"88.0.4324.146-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
