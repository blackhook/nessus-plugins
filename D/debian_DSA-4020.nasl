#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4020. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104414);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15386", "CVE-2017-15387", "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391", "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395", "CVE-2017-15396", "CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127", "CVE-2017-5128", "CVE-2017-5129", "CVE-2017-5131", "CVE-2017-5132", "CVE-2017-5133");
  script_xref(name:"DSA", value:"4020");

  script_name(english:"Debian DSA-4020-1 : chromium-browser - security update");
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

In addition, this message serves as an annoucment that security
support for chromium in the oldstable release (jessie), Debian 8, is
now discontinued.

Debian 8 chromium users that desire continued security updates are
strongly encouraged to upgrade now to the current stable release
(stretch), Debian 9.

An alternative is to switch to the firefox browser, which will
continue to receive security updates in jessie for some time.

  - CVE-2017-5124
    A cross-site scripting issue was discovered in MHTML.

  - CVE-2017-5125
    A heap overflow issue was discovered in the skia
    library.

  - CVE-2017-5126
    Luat Nguyen discovered a use-after-free issue in the
    pdfium library.

  - CVE-2017-5127
    Luat Nguyen discovered another use-after-free issue in
    the pdfium library.

  - CVE-2017-5128
    Omair discovered a heap overflow issue in the WebGL
    implementation.

  - CVE-2017-5129
    Omair discovered a use-after-free issue in the WebAudio
    implementation.

  - CVE-2017-5131
    An out-of-bounds write issue was discovered in the skia
    library.

  - CVE-2017-5132
    Guarav Dewan discovered an error in the WebAssembly
    implementation.

  - CVE-2017-5133
    Aleksandar Nikolic discovered an out-of-bounds write
    issue in the skia library.

  - CVE-2017-15386
    WenXu Wu discovered a user interface spoofing issue.

  - CVE-2017-15387
    Jun Kokatsu discovered a way to bypass the content
    security policy.

  - CVE-2017-15388
    Kushal Arvind Shah discovered an out-of-bounds read
    issue in the skia library.

  - CVE-2017-15389
    xisigr discovered a URL spoofing issue.

  - CVE-2017-15390
    Haosheng Wang discovered a URL spoofing issue.

  - CVE-2017-15391
    Joao Lucas Melo Brasio discovered a way for an extension
    to bypass its limitations.

  - CVE-2017-15392
    Xiaoyin Liu discovered an error the implementation of
    registry keys.

  - CVE-2017-15393
    Svyat Mitin discovered an issue in the devtools.

  - CVE-2017-15394
    Sam discovered a URL spoofing issue.

  - CVE-2017-15395
    Johannes Bergman discovered a NULL pointer dereference
    issue.

  - CVE-2017-15396
    Yuan Deng discovered a stack overflow issue in the v8
    JavaScript library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4020"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the oldstable distribution (jessie), security support for chromium
has been discontinued.

For the stable distribution (stretch), these problems have been fixed
in version 62.0.3202.75-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"62.0.3202.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"62.0.3202.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"62.0.3202.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"62.0.3202.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"62.0.3202.75-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"62.0.3202.75-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
