#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2724. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68970);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-2853", "CVE-2013-2867", "CVE-2013-2868", "CVE-2013-2869", "CVE-2013-2870", "CVE-2013-2871", "CVE-2013-2873", "CVE-2013-2875", "CVE-2013-2876", "CVE-2013-2877", "CVE-2013-2878", "CVE-2013-2879", "CVE-2013-2880");
  script_bugtraq_id(61046, 61047, 61049, 61050, 61051, 61052, 61054, 61055, 61056, 61057, 61059, 61060, 61061);
  script_xref(name:"DSA", value:"2724");

  script_name(english:"Debian DSA-2724-1 : chromium-browser - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Chromium web
browser.

  - CVE-2013-2853
    The HTTPS implementation does not ensure that headers
    are terminated by \r\n\r\n (carriage return, newline,
    carriage return, newline).

  - CVE-2013-2867
    Chrome does not properly prevent pop-under windows.

  - CVE-2013-2868
    common/extensions/sync_helper.cc proceeds with sync
    operations for NPAPI extensions without checking for a
    certain plugin permission setting.

  - CVE-2013-2869
    Denial of service (out-of-bounds read) via a crafted
    JPEG2000 image.

  - CVE-2013-2870
    Use-after-free vulnerability in network sockets.

  - CVE-2013-2871
    Use-after-free vulnerability in input handling.

  - CVE-2013-2873
    Use-after-free vulnerability in resource loading.

  - CVE-2013-2875
    Out-of-bounds read in SVG file handling.

  - CVE-2013-2876
    Chromium does not properly enforce restrictions on the
    capture of screenshots by extensions, which could lead
    to information disclosure from previous page visits.

  - CVE-2013-2877
    Out-of-bounds read in XML file handling.

  - CVE-2013-2878
    Out-of-bounds read in text handling.

  - CVE-2013-2879
    The circumstances in which a renderer process can be
    considered a trusted process for sign-in and subsequent
    sync operations were not propertly checked.

  - CVE-2013-2880
    The Chromium 28 development team found various issues
    from internal fuzzing, audits, and other studies."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2013/dsa-2724"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 28.0.1500.71-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"28.0.1500.71-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"28.0.1500.71-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"28.0.1500.71-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"28.0.1500.71-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"28.0.1500.71-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"28.0.1500.71-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"28.0.1500.71-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"28.0.1500.71-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
