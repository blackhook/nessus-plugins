#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1392. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27547);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_xref(name:"DSA", value:"1392");

  script_name(english:"Debian DSA-1392-1 : xulrunner - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2007-1095
    Michal Zalewski discovered that the unload event handler
    had access to the address of the next page to be loaded,
    which could allow information disclosure or spoofing.

  - CVE-2007-2292
    Stefano Di Paola discovered that insufficient validation
    of user names used in Digest authentication on a website
    allows HTTP response splitting attacks.

  - CVE-2007-3511
    It was discovered that insecure focus handling of the
    file upload control can lead to information disclosure.
    This is a variant of CVE-2006-2894.

  - CVE-2007-5334
    Eli Friedman discovered that web pages written in Xul
    markup can hide the titlebar of windows, which can lead
    to spoofing attacks.

  - CVE-2007-5337
    Georgi Guninski discovered the insecure handling of
    smb:// and sftp:// URI schemes may lead to information
    disclosure. This vulnerability is only exploitable if
    Gnome-VFS support is present on the system.

  - CVE-2007-5338
    'moz_bug_r_a4' discovered that the protection scheme
    offered by XPCNativeWrappers could be bypassed, which
    might allow privilege escalation.

  - CVE-2007-5339
    L. David Baron, Boris Zbarsky, Georgi Guninski, Paul
    Nickerson, Olli Pettay, Jesse Ruderman, Vladimir Sukhoy,
    Daniel Veditz, and Martijn Wargers discovered crashes in
    the layout engine, which might allow the execution of
    arbitrary code.

  - CVE-2007-5340
    Igor Bukanov, Eli Friedman, and Jesse Ruderman
    discovered crashes in the JavaScript engine, which might
    allow the execution of arbitrary code.

The oldstable distribution (sarge) doesn't contain xulrunner."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2007/dsa-1392"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (etch) these problems have been fixed in
version 1.8.0.14~pre071019b-0etch1. Builds for hppa and mipsel will be
provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"libmozillainterfaces-java", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs-dev", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d-dbg", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d-dbg", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-dev", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d-dbg", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-dev", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-tools", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs-dev", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs1", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-common", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-dev", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d-dbg", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-xpcom", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"spidermonkey-bin", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner", reference:"1.8.0.14~pre071019b-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner-gnome-support", reference:"1.8.0.14~pre071019b-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
