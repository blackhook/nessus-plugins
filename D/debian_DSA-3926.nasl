#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3926. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102210);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-5087", "CVE-2017-5088", "CVE-2017-5089", "CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094", "CVE-2017-5095", "CVE-2017-5097", "CVE-2017-5098", "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-5105", "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", "CVE-2017-5110", "CVE-2017-7000");
  script_xref(name:"DSA", value:"3926");

  script_name(english:"Debian DSA-3926-1 : chromium-browser - security update");
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

  - CVE-2017-5087
    Ned Williamson discovered a way to escape the sandbox.

  - CVE-2017-5088
    Xiling Gong discovered an out-of-bounds read issue in
    the v8 JavaScript library.

  - CVE-2017-5089
    Michal Bentkowski discovered a spoofing issue.

  - CVE-2017-5091
    Ned Williamson discovered a use-after-free issue in
    IndexedDB.

  - CVE-2017-5092
    Yu Zhou discovered a use-after-free issue in PPAPI.

  - CVE-2017-5093
    Luan Herrera discovered a user interface spoofing issue.

  - CVE-2017-5094
    A type confusion issue was discovered in extensions.

  - CVE-2017-5095
    An out-of-bounds write issue was discovered in the
    pdfium library.

  - CVE-2017-5097
    An out-of-bounds read issue was discovered in the skia
    library.

  - CVE-2017-5098
    Jihoon Kim discovered a use-after-free issue in the v8
    JavaScript library.

  - CVE-2017-5099
    Yuan Deng discovered an out-of-bounds write issue in
    PPAPI.

  - CVE-2017-5100
    A use-after-free issue was discovered in Chrome Apps.

  - CVE-2017-5101
    Luan Herrera discovered a URL spoofing issue.

  - CVE-2017-5102
    An uninitialized variable was discovered in the skia
    library.

  - CVE-2017-5103
    Another uninitialized variable was discovered in the
    skia library.

  - CVE-2017-5104
    Khalil Zhani discovered a user interface spoofing issue.

  - CVE-2017-5105
    Rayyan Bijoora discovered a URL spoofing issue.

  - CVE-2017-5106
    Jack Zac discovered a URL spoofing issue.

  - CVE-2017-5107
    David Kohlbrenner discovered an information leak in SVG
    file handling.

  - CVE-2017-5108
    Guang Gong discovered a type confusion issue in the
    pdfium library.

  - CVE-2017-5109
    Jose Maria Acuna Morgado discovered a user interface
    spoofing issue.

  - CVE-2017-5110
    xisigr discovered a way to spoof the payments dialog.

  - CVE-2017-7000
    Chaitin Security Research Lab discovered an information
    disclosure issue in the sqlite library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3926"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (stretch), these problems have been fixed
in version 60.0.3112.78-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/07");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"60.0.3112.78-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"60.0.3112.78-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"60.0.3112.78-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"60.0.3112.78-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"60.0.3112.78-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"60.0.3112.78-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
