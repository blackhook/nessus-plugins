#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3590. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91429);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-1667", "CVE-2016-1668", "CVE-2016-1669", "CVE-2016-1670", "CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675", "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679", "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687", "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691", "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695");
  script_xref(name:"DSA", value:"3590");

  script_name(english:"Debian DSA-3590-1 : chromium-browser - security update");
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

  - CVE-2016-1667
    Mariusz Mylinski discovered a cross-origin bypass.

  - CVE-2016-1668
    Mariusz Mylinski discovered a cross-origin bypass in
    bindings to v8.

  - CVE-2016-1669
    Choongwoo Han discovered a buffer overflow in the v8
    JavaScript library.

  - CVE-2016-1670
    A race condition was found that could cause the renderer
    process to reuse ids that should have been unique.

  - CVE-2016-1672
    Mariusz Mylinski discovered a cross-origin bypass in
    extension bindings.

  - CVE-2016-1673
    Mariusz Mylinski discovered a cross-origin bypass in
    Blink/Webkit.

  - CVE-2016-1674
    Mariusz Mylinski discovered another cross-origin bypass
    in extension bindings.

  - CVE-2016-1675
    Mariusz Mylinski discovered another cross-origin bypass
    in Blink/Webkit.

  - CVE-2016-1676
    Rob Wu discovered a cross-origin bypass in extension
    bindings.

  - CVE-2016-1677
    Guang Gong discovered a type confusion issue in the v8
    JavaScript library.

  - CVE-2016-1678
    Christian Holler discovered an overflow issue in the v8
    JavaScript library.

  - CVE-2016-1679
    Rob Wu discovered a use-after-free issue in the bindings
    to v8.

  - CVE-2016-1680
    Atte Kettunen discovered a use-after-free issue in the
    skia library.

  - CVE-2016-1681
    Aleksandar Nikolic discovered an overflow issue in the
    pdfium library.

  - CVE-2016-1682
    KingstonTime discovered a way to bypass the Content
    Security Policy.

  - CVE-2016-1683
    Nicolas Gregoire discovered an out-of-bounds write issue
    in the libxslt library.

  - CVE-2016-1684
    Nicolas Gregoire discovered an integer overflow issue in
    the libxslt library.

  - CVE-2016-1685
    Ke Liu discovered an out-of-bounds read issue in the
    pdfium library.

  - CVE-2016-1686
    Ke Liu discovered another out-of-bounds read issue in
    the pdfium library.

  - CVE-2016-1687
    Rob Wu discovered an information leak in the handling of
    extensions.

  - CVE-2016-1688
    Max Korenko discovered an out-of-bounds read issue in
    the v8 JavaScript library.

  - CVE-2016-1689
    Rob Wu discovered a buffer overflow issue.

  - CVE-2016-1690
    Rob Wu discovered a use-after-free issue.

  - CVE-2016-1691
    Atte Kettunen discovered a buffer overflow issue in the
    skia library.

  - CVE-2016-1692
    Til Jasper Ullrich discovered a cross-origin bypass
    issue.

  - CVE-2016-1693
    Khalil Zhani discovered that the Software Removal Tool
    download was done over an HTTP connection.

  - CVE-2016-1694
    Ryan Lester and Bryant Zadegan discovered that pinned
    public keys would be removed when clearing the browser
    cache.

  - CVE-2016-1695
    The chrome development team found and fixed various
    issues during internal auditing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3590"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 51.0.2704.63-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"51.0.2704.63-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
