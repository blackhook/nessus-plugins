#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1999-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131138);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-18886", "CVE-2019-18887", "CVE-2019-18888");

  script_name(english:"Debian DLA-1999-1 : symfony security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in the Symfony PHP framework
which could lead to a timing attack/information leak, argument
injection and code execution via unserialization.

For Debian 8 'Jessie', these problems have been fixed in version
2.3.21+dfsg-4+deb8u6.

We recommend that you upgrade your symfony packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/symfony"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-browser-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-class-loader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-classloader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-css-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dependency-injection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-doctrine-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dom-crawler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-event-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-eventdispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-finder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-form");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-framework-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-http-foundation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-http-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-monolog-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-options-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-propel1-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-property-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-proxy-manager-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-routing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-serializer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-stopwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-swiftmailer-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-templating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-translation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-twig-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-twig-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-web-profiler-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-yaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"php-symfony-browser-kit", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-class-loader", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-classloader", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-config", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-console", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-css-selector", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-debug", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dependency-injection", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-doctrine-bridge", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dom-crawler", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-event-dispatcher", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-eventdispatcher", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-filesystem", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-finder", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-form", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-framework-bundle", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-foundation", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-kernel", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-intl", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-locale", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-monolog-bridge", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-options-resolver", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-process", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-propel1-bridge", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-property-access", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-proxy-manager-bridge", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-routing", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security-bundle", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-serializer", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-stopwatch", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-swiftmailer-bridge", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-templating", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-translation", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bridge", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bundle", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-validator", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-web-profiler-bundle", reference:"2.3.21+dfsg-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-yaml", reference:"2.3.21+dfsg-4+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
