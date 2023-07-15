#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4237. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110820);
  script_version("1.8");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2018-6118", "CVE-2018-6120", "CVE-2018-6121", "CVE-2018-6122", "CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126", "CVE-2018-6127", "CVE-2018-6129", "CVE-2018-6130", "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134", "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138", "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142", "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147", "CVE-2018-6148", "CVE-2018-6149");
  script_xref(name:"DSA", value:"4237");

  script_name(english:"Debian DSA-4237-1 : chromium-browser - security update");
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

  - CVE-2018-6118
    Ned Williamson discovered a use-after-free issue.

  - CVE-2018-6120
    Zhou Aiting discovered a buffer overflow issue in the
    pdfium library.

  - CVE-2018-6121
    It was discovered that malicious extensions could
    escalate privileges.

  - CVE-2018-6122
    A type confusion issue was discovered in the v8
    JavaScript library.

  - CVE-2018-6123
    Looben Yang discovered a use-after-free issue.

  - CVE-2018-6124
    Guang Gong discovered a type confusion issue.

  - CVE-2018-6125
    Yubico discovered that the WebUSB implementation was too
    permissive.

  - CVE-2018-6126
    Ivan Fratric discovered a buffer overflow issue in the
    skia library.

  - CVE-2018-6127
    Looben Yang discovered a use-after-free issue.

  - CVE-2018-6129
    Natalie Silvanovich discovered an out-of-bounds read
    issue in WebRTC.

  - CVE-2018-6130
    Natalie Silvanovich discovered an out-of-bounds read
    issue in WebRTC.

  - CVE-2018-6131
    Natalie Silvanovich discovered an error in WebAssembly.

  - CVE-2018-6132
    Ronald E. Crane discovered an uninitialized memory
    issue.

  - CVE-2018-6133
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6134
    Jun Kokatsu discovered a way to bypass the Referrer
    Policy.

  - CVE-2018-6135
    Jasper Rebane discovered a user interface spoofing
    issue.

  - CVE-2018-6136
    Peter Wong discovered an out-of-bounds read issue in the
    v8 JavaScript library.

  - CVE-2018-6137
    Michael Smith discovered an information leak.

  - CVE-2018-6138
    Francois Lajeunesse-Robert discovered that the
    extensions policy was too permissive.

  - CVE-2018-6139
    Rob Wu discovered a way to bypass restrictions in the
    debugger extension.

  - CVE-2018-6140
    Rob Wu discovered a way to bypass restrictions in the
    debugger extension.

  - CVE-2018-6141
    Yangkang discovered a buffer overflow issue in the skia
    library.

  - CVE-2018-6142
    Choongwoo Han discovered an out-of-bounds read in the v8
    JavaScript library.

  - CVE-2018-6143
    Guang Gong discovered an out-of-bounds read in the v8
    JavaScript library.

  - CVE-2018-6144
    pdknsk discovered an out-of-bounds read in the pdfium
    library.

  - CVE-2018-6145
    Masato Kinugawa discovered an error in the MathML
    implementation.

  - CVE-2018-6147
    Michail Pishchagin discovered an error in password entry
    fields.

  - CVE-2018-6148
    Michal Bentkowski discovered that the Content Security
    Policy header was handled incorrectly.

  - CVE-2018-6149
    Yu Zhou and Jundong Xie discovered an out-of-bounds
    write issue in the v8 JavaScript library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6149"
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
    value:"https://www.debian.org/security/2018/dsa-4237"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (stretch), these problems have been fixed
in version 67.0.3396.87-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/02");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"67.0.3396.87-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"67.0.3396.87-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"67.0.3396.87-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"67.0.3396.87-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"67.0.3396.87-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"67.0.3396.87-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
