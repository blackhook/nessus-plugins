#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4917. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149635);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520");
  script_xref(name:"DSA", value:"4917");

  script_name(english:"Debian DSA-4917-1 : chromium - security update");
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

  - CVE-2021-30506
    @retsew0x01 discovered an error in the Web App
    installation interface.

  - CVE-2021-30507
    Alison Huffman discovered an error in the Offline mode.

  - CVE-2021-30508
    Leecraso and Guang Gong discovered a buffer overflow
    issue in the Media Feeds implementation.

  - CVE-2021-30509
    David Erceg discovered an out-of-bounds write issue in
    the Tab Strip implementation.

  - CVE-2021-30510
    Weipeng Jiang discovered a race condition in the aura
    window manager.

  - CVE-2021-30511
    David Erceg discovered an out-of-bounds read issue in
    the Tab Strip implementation.

  - CVE-2021-30512
    ZhanJia Song discovered a use-after-free issue in the
    notifications implementation.

  - CVE-2021-30513
    Man Yue Mo discovered an incorrect type in the v8
    JavaScript library.

  - CVE-2021-30514
    koocola and Wang discovered a use-after-free issue in
    the Autofill feature.

  - CVE-2021-30515
    Rong Jian and Guang Gong discovered a use-after-free
    issue in the file system access API.

  - CVE-2021-30516
    ZhanJia Song discovered a buffer overflow issue in the
    browsing history.

  - CVE-2021-30517
    Jun Kokatsu discovered a buffer overflow issue in the
    reader mode.

  - CVE-2021-30518
    laural discovered use of an incorrect type in the v8
    JavaScript library.

  - CVE-2021-30519
    asnine discovered a use-after-free issue in the Payments
    feature.

  - CVE-2021-30520
    Khalil Zhani discovered a use-after-free issue in the
    Tab Strip implementation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-30520"
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
    value:"https://www.debian.org/security/2021/dsa-4917"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the stable distribution (buster), these problems have been fixed
in version 90.0.4430.212-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30520");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"chromium", reference:"90.0.4430.212-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"90.0.4430.212-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"90.0.4430.212-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"90.0.4430.212-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"90.0.4430.212-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"90.0.4430.212-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
