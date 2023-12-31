#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2862. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72538);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-6641", "CVE-2013-6643", "CVE-2013-6644", "CVE-2013-6645", "CVE-2013-6646", "CVE-2013-6649", "CVE-2013-6650");
  script_bugtraq_id(64805, 64981, 65168, 65172);
  script_xref(name:"DSA", value:"2862");

  script_name(english:"Debian DSA-2862-1 : chromium-browser - several vulnerabilities");
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

  - CVE-2013-6641
    Atte Kettunen discovered a use-after-free issue in
    Blink/Webkit form elements.

  - CVE-2013-6643
    Joao Lucas Melo Brasio discovered a Google account
    information disclosure issue related to the one-click
    sign-on feature.

  - CVE-2013-6644
    The chrome development team discovered and fixed
    multiple issues with potential security impact. 

  - CVE-2013-6645
    Khalil Zhani discovered a use-after-free issue related
    to speech input.

  - CVE-2013-6646
    Colin Payne discovered a use-after-free issue in the web
    workers implementation. 

  - CVE-2013-6649
    Atte Kettunen discovered a use-after-free issue in the
    Blink/Webkit SVG implementation.

  - CVE-2013-6650
    Christian Holler discovered a memory corruption in the
    v8 JavaScript library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-2862"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 32.0.1700.123-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"32.0.1700.123-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"32.0.1700.123-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"32.0.1700.123-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"32.0.1700.123-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"32.0.1700.123-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"32.0.1700.123-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"32.0.1700.123-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"32.0.1700.123-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
