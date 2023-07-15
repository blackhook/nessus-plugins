#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3315. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84992);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-1266", "CVE-2015-1267", "CVE-2015-1268", "CVE-2015-1269", "CVE-2015-1270", "CVE-2015-1271", "CVE-2015-1272", "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1278", "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1282", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1286", "CVE-2015-1287", "CVE-2015-1288", "CVE-2015-1289");
  script_bugtraq_id(75332, 75333, 75334, 75336, 75973);
  script_xref(name:"DSA", value:"3315");

  script_name(english:"Debian DSA-3315-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the chromium web browser.

  - CVE-2015-1266
    Intended access restrictions could be bypassed for
    certain URLs like chrome://gpu.

  - CVE-2015-1267
    A way to bypass the Same Origin Policy was discovered.

  - CVE-2015-1268
    Mariusz Mlynski also discovered a way to bypass the Same
    Origin Policy.

  - CVE-2015-1269
    Mike Rudy discovered that hostnames were not properly
    compared in the HTTP Strict Transport Policy and HTTP
    Public Key Pinning features, which could allow those
    access restrictions to be bypassed.

  - CVE-2015-1270
    Atte Kettunen discovered an uninitialized memory read in
    the ICU library.

  - CVE-2015-1271
    cloudfuzzer discovered a buffer overflow in the pdfium
    library.

  - CVE-2015-1272
    Chamal de Silva discovered race conditions in the GPU
    process implementation.

  - CVE-2015-1273
    makosoft discovered a buffer overflow in openjpeg, which
    is used by the pdfium library embedded in chromium.

  - CVE-2015-1274
    andrewm.bpi discovered that the auto-open list allowed
    certain file types to be executed immediately after
    download.

  - CVE-2015-1276
    Colin Payne discovered a use-after-free issue in the
    IndexedDB implementation.

  - CVE-2015-1277
    SkyLined discovered a use-after-free issue in chromium's
    accessibility implementation.

  - CVE-2015-1278
    Chamal de Silva discovered a way to use PDF documents to
    spoof a URL.

  - CVE-2015-1279
    mlafon discovered a buffer overflow in the pdfium
    library.

  - CVE-2015-1280
    cloudfuzzer discovered a memory corruption issue in the
    SKIA library.

  - CVE-2015-1281
    Masato Knugawa discovered a way to bypass the Content
    Security Policy.

  - CVE-2015-1282
    Chamal de Silva discovered multiple use-after-free
    issues in the pdfium library.

  - CVE-2015-1283
    Huzaifa Sidhpurwala discovered a buffer overflow in the
    expat library.

  - CVE-2015-1284
    Atte Kettunen discovered that the maximum number of page
    frames was not correctly checked.

  - CVE-2015-1285
    gazheyes discovered an information leak in the XSS
    auditor, which normally helps to prevent certain classes
    of cross-site scripting problems.

  - CVE-2015-1286
    A cross-site scripting issue was discovered in the
    interface to the v8 JavaScript library.

  - CVE-2015-1287
    filedescriptor discovered a way to bypass the Same
    Origin Policy.

  - CVE-2015-1288
    Mike Ruddy discovered that the spellchecking
    dictionaries could still be downloaded over plain HTTP
    (related to CVE-2015-1263 ).

  - CVE-2015-1289
    The chrome 44 development team found and fixed various
    issues during internal auditing.

In addition to the above issues, Google disabled the hotword extension
by default in this version, which if enabled downloads files without
the user's intervention."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3315"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 44.0.2403.89-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"44.0.2403.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"44.0.2403.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"44.0.2403.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"44.0.2403.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"44.0.2403.89-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
