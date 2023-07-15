#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4289. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117370);
  script_version("1.5");
  script_cvs_date("Date: 2019/01/17 10:53:30");

  script_cve_id("CVE-2018-16065", "CVE-2018-16066", "CVE-2018-16067");
  script_xref(name:"DSA", value:"4289");

  script_name(english:"Debian DSA-4289-1 : chromium-browser - security update");
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

  - CVE-2018-16065
    Brendon Tiszka discovered an out-of-bounds write issue
    in the v8 JavaScript library.

  - CVE-2018-16066
    cloudfuzzer discovered an out-of-bounds read issue in
    blink/webkit.

  - CVE-2018-16067
    Zhe Jin discovered an out-of-bounds read issue in the
    WebAudio implementation.

  - CVE-2018-16068
    Mark Brand discovered an out-of-bounds write issue in
    the Mojo message passing library.

  - CVE-2018-16069
    Mark Brand discovered an out-of-bounds read issue in the
    swiftshader library.

  - CVE-2018-16070
    Ivan Fratric discovered an integer overflow issue in the
    skia library.

  - CVE-2018-16071
    Natalie Silvanovich discovered a use-after-free issue in
    the WebRTC implementation.

  - CVE-2018-16073
    Jun Kokatsu discovered an error in the Site Isolation
    feature when restoring browser tabs.

  - CVE-2018-16074
    Jun Kokatsu discovered an error in the Site Isolation
    feature when using a Blob URL.

  - CVE-2018-16075
    Pepe Vila discovered an error that could allow remote
    sites to access local files.

  - CVE-2018-16076
    Aseksandar Nikolic discovered an out-of-bounds read
    issue in the pdfium library.

  - CVE-2018-16077
    Manuel Caballero discovered a way to bypass the Content
    Security Policy.

  - CVE-2018-16078
    Cailan Sacks discovered that the Autofill feature could
    leak saved credit card information.

  - CVE-2018-16079
    Markus Vervier and Michele Orru discovered a URL
    spoofing issue.

  - CVE-2018-16080
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-16081
    Jann Horn discovered that local files could be accessed
    in the developer tools.

  - CVE-2018-16082
    Omair discovered a buffer overflow issue in the
    swiftshader library.

  - CVE-2018-16083
    Natalie Silvanovich discovered an out-of-bounds read
    issue in the WebRTC implementation.

  - CVE-2018-16084
    Jun Kokatsu discovered a way to bypass a user
    confirmation dialog.

  - CVE-2018-16085
    Roman Kuksin discovered a use-after-free issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16085"
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
    value:"https://www.debian.org/security/2018/dsa-4289"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (stretch), these problems have been fixed
in version 69.0.3497.81-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"69.0.3497.81-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"69.0.3497.81-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"69.0.3497.81-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"69.0.3497.81-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"69.0.3497.81-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"69.0.3497.81-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
