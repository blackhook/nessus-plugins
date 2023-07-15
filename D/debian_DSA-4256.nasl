#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4256. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111360);
  script_version("1.8");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6150", "CVE-2018-6151", "CVE-2018-6152", "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179");
  script_xref(name:"DSA", value:"4256");

  script_name(english:"Debian DSA-4256-1 : chromium-browser - security update");
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

  - CVE-2018-4117
    AhsanEjaz discovered an information leak.

  - CVE-2018-6044
    Rob Wu discovered a way to escalate privileges using
    extensions.

  - CVE-2018-6150
    Rob Wu discovered an information disclosure issue (this
    problem was fixed in a previous release but was
    mistakenly omitted from upstream's announcement at the
    time).

  - CVE-2018-6151
    Rob Wu discovered an issue in the developer tools (this
    problem was fixed in a previous release but was
    mistakenly omitted from upstream's announcement at the
    time).

  - CVE-2018-6152
    Rob Wu discovered an issue in the developer tools (this
    problem was fixed in a previous release but was
    mistakenly omitted from upstream's announcement at the
    time).

  - CVE-2018-6153
    Zhen Zhou discovered a buffer overflow issue in the skia
    library.

  - CVE-2018-6154
    Omair discovered a buffer overflow issue in the WebGL
    implementation.

  - CVE-2018-6155
    Natalie Silvanovich discovered a use-after-free issue in
    the WebRTC implementation.

  - CVE-2018-6156
    Natalie Silvanovich discovered a buffer overflow issue
    in the WebRTC implementation.

  - CVE-2018-6157
    Natalie Silvanovich discovered a type confusion issue in
    the WebRTC implementation.

  - CVE-2018-6158
    Zhe Jin discovered a use-after-free issue.

  - CVE-2018-6159
    Jun Kokatsu discovered a way to bypass the same origin
    policy.

  - CVE-2018-6161
    Jun Kokatsu discovered a way to bypass the same origin
    policy.

  - CVE-2018-6162
    Omair discovered a buffer overflow issue in the WebGL
    implementation.

  - CVE-2018-6163
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6164
    Jun Kokatsu discovered a way to bypass the same origin
    policy.

  - CVE-2018-6165
    evil1m0 discovered a URL spoofing issue.

  - CVE-2018-6166
    Lynas Zhang discovered a URL spoofing issue.

  - CVE-2018-6167
    Lynas Zhang discovered a URL spoofing issue.

  - CVE-2018-6168
    Gunes Acar and Danny Y. Huang discovered a way to bypass
    the Cross Origin Resource Sharing policy.

  - CVE-2018-6169
    Sam P discovered a way to bypass permissions when
    installing extensions.

  - CVE-2018-6170
    A type confusion issue was discovered in the pdfium
    library.

  - CVE-2018-6171
    A use-after-free issue was discovered in the
    WebBluetooth implementation.

  - CVE-2018-6172
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6173
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6174
    Mark Brand discovered an integer overflow issue in the
    swiftshader library.

  - CVE-2018-6175
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6176
    Jann Horn discovered a way to escalate privileges using
    extensions.

  - CVE-2018-6177
    Ron Masas discovered an information leak.

  - CVE-2018-6178
    Khalil Zhani discovered a user interface spoofing issue.

  - CVE-2018-6179
    It was discovered that information about files local to
    the system could be leaked to extensions.

This version also fixes a regression introduced in the previous
security update that could prevent decoding of particular audio/video
codecs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-4117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6179"
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
    value:"https://www.debian.org/security/2018/dsa-4256"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (stretch), these problems have been fixed
in version 68.0.3440.75-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/27");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"68.0.3440.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"68.0.3440.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"68.0.3440.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"68.0.3440.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"68.0.3440.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"68.0.3440.75-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
