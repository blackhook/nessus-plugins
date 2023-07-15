#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4352. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119509);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/09");

  script_cve_id("CVE-2018-17480", "CVE-2018-17481", "CVE-2018-18335", "CVE-2018-18336", "CVE-2018-18337", "CVE-2018-18338", "CVE-2018-18339", "CVE-2018-18340", "CVE-2018-18341", "CVE-2018-18342", "CVE-2018-18343", "CVE-2018-18344", "CVE-2018-18345", "CVE-2018-18346", "CVE-2018-18347", "CVE-2018-18348", "CVE-2018-18349", "CVE-2018-18350", "CVE-2018-18351", "CVE-2018-18352", "CVE-2018-18353", "CVE-2018-18354", "CVE-2018-18355", "CVE-2018-18356", "CVE-2018-18357", "CVE-2018-18358", "CVE-2018-18359");
  script_xref(name:"DSA", value:"4352");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Debian DSA-4352-1 : chromium-browser - security update");
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

  - CVE-2018-17480
    Guang Gong discovered an out-of-bounds write issue in
    the v8 JavaScript library.

  - CVE-2018-17481
    Several use-after-free issues were discovered in the
    pdfium library.

  - CVE-2018-18335
    A buffer overflow issue was discovered in the skia
    library.

  - CVE-2018-18336
    Huyna discovered a use-after-free issue in the pdfium
    library.

  - CVE-2018-18337
    cloudfuzzer discovered a use-after-free issue in
    blink/webkit.

  - CVE-2018-18338
    Zhe Jin discovered a buffer overflow issue in the canvas
    renderer.

  - CVE-2018-18339
    cloudfuzzer discovered a use-after-free issue in the
    WebAudio implementation.

  - CVE-2018-18340
    A use-after-free issue was discovered in the
    MediaRecorder implementation.

  - CVE-2018-18341
    cloudfuzzer discovered a buffer overflow issue in
    blink/webkit.

  - CVE-2018-18342
    Guang Gong discovered an out-of-bounds write issue in
    the v8 JavaScript library.

  - CVE-2018-18343
    Tran Tien Hung discovered a use-after-free issue in the
    skia library.

  - CVE-2018-18344
    Jann Horn discovered an error in the Extensions
    implementation.

  - CVE-2018-18345
    Masato Kinugawa and Jun Kokatsu discovered an error in
    the Site Isolation feature.

  - CVE-2018-18346
    Luan Herrera discovered an error in the user interface.

  - CVE-2018-18347
    Luan Herrera discovered an error in the Navigation
    implementation.

  - CVE-2018-18348
    Ahmed Elsobky discovered an error in the omnibox
    implementation.

  - CVE-2018-18349
    David Erceg discovered a policy enforcement error.

  - CVE-2018-18350
    Jun Kokatsu discovered a policy enforcement error.

  - CVE-2018-18351
    Jun Kokatsu discovered a policy enforcement error.

  - CVE-2018-18352
    Jun Kokatsu discovered an error in Media handling.

  - CVE-2018-18353
    Wenxu Wu discovered an error in the network
    authentication implementation.

  - CVE-2018-18354
    Wenxu Wu discovered an error related to integration with
    GNOME Shell.

  - CVE-2018-18355
    evil1m0 discovered a policy enforcement error.

  - CVE-2018-18356
    Tran Tien Hung discovered a use-after-free issue in the
    skia library.

  - CVE-2018-18357
    evil1m0 discovered a policy enforcement error.

  - CVE-2018-18358
    Jann Horn discovered a policy enforcement error.

  - CVE-2018-18359
    cyrilliu discovered an out-of-bounds read issue in the
    v8 JavaScript library.

Several additional security relevant issues are also fixed in this
update that have not yet received CVE identifiers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-17480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-17481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18359"
  );
  # https://security-tracker.debian.org/tracker/source-package/chromium-browser
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e33901a2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4352"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (stretch), these problems have been fixed
in version 71.0.3578.80-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18359");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"71.0.3578.80-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"71.0.3578.80-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"71.0.3578.80-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"71.0.3578.80-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"71.0.3578.80-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"71.0.3578.80-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
