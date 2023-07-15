#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4103. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106537);
  script_version("3.8");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2017-15420", "CVE-2017-15429", "CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033", "CVE-2018-6034", "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038", "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041", "CVE-2018-6042", "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046", "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050", "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054");
  script_xref(name:"DSA", value:"4103");

  script_name(english:"Debian DSA-4103-1 : chromium-browser - security update");
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

  - CVE-2017-15420
    Drew Springall discovered a URL spoofing issue.

  - CVE-2017-15429
    A cross-site scripting issue was discovered in the v8
    JavaScript library.

  - CVE-2018-6031
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2018-6032
    Jun Kokatsu discovered a way to bypass the same origin
    policy.

  - CVE-2018-6033
    Juho Nurminen discovered a race condition when opening
    downloaded files.

  - CVE-2018-6034
    Tobias Klein discovered an integer overflow issue.

  - CVE-2018-6035
    Rob Wu discovered a way for extensions to access
    devtools.

  - CVE-2018-6036
    UK's National Cyber Security Centre discovered an
    integer overflow issue.

  - CVE-2018-6037
    Paul Stone discovered an issue in the autofill feature.

  - CVE-2018-6038
    cloudfuzzer discovered a buffer overflow issue.

  - CVE-2018-6039
    Juho Nurminen discovered a cross-site scripting issue in
    the developer tools.

  - CVE-2018-6040
    WenXu Wu discovered a way to bypass the content security
    policy.

  - CVE-2018-6041
    Luan Herrera discovered a URL spoofing issue.

  - CVE-2018-6042
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6043
    A character escaping issue was discovered.

  - CVE-2018-6045
    Rob Wu discovered a way for extensions to access
    devtools.

  - CVE-2018-6046
    Rob Wu discovered a way for extensions to access
    devtools.

  - CVE-2018-6047
    Masato Kinugawa discovered an information leak issue.

  - CVE-2018-6048
    Jun Kokatsu discovered a way to bypass the referrer
    policy.

  - CVE-2018-6049
    WenXu Wu discovered a user interface spoofing issue.

  - CVE-2018-6050
    Jonathan Kew discovered a URL spoofing issue.

  - CVE-2018-6051
    Antonio Sanso discovered an information leak issue.

  - CVE-2018-6052
    Tanner Emek discovered that the referrer policy
    implementation was incomplete.

  - CVE-2018-6053
    Asset Kabdenov discovered an information leak issue.

  - CVE-2018-6054
    Rob Wu discovered a use-after-free issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6054"
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
    value:"https://www.debian.org/security/2018/dsa-4103"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the oldstable distribution (jessie), security support for chromium
has been discontinued.

For the stable distribution (stretch), these problems have been fixed
in version 64.0.3282.119-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/01");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"64.0.3282.119-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"64.0.3282.119-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"64.0.3282.119-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"64.0.3282.119-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"64.0.3282.119-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"64.0.3282.119-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
