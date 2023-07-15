#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1707-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122721);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-16652", "CVE-2017-16654", "CVE-2018-11385", "CVE-2018-11408", "CVE-2018-14773", "CVE-2018-19789", "CVE-2018-19790");

  script_name(english:"Debian DLA-1707-1 : symfony security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities have been discovered in symfony, a
PHP web application framework. Numerous symfony components are
affected: Security, bundle readers, session handling, SecurityBundle,
HttpFoundation, Form, and Security\Http.

The corresponding upstream advisories contain further details :

[CVE-2017-16652]
https://symfony.com/blog/cve-2017-16652-open-redirect-vulnerability-on
-security-handlers

[CVE-2017-16654]
https://symfony.com/blog/cve-2017-16654-intl-bundle-readers-breaking-o
ut-of-paths

[CVE-2018-11385]
https://symfony.com/blog/cve-2018-11385-session-fixation-issue-for-gua
rd-authentication

[CVE-2018-11408]
https://symfony.com/blog/cve-2018-11408-open-redirect-vulnerability-on
-security-handlers

[CVE-2018-14773]
https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-
risky-http-headers

[CVE-2018-19789]
https://symfony.com/blog/cve-2018-19789-disclosure-of-uploaded-files-f
ull-path

[CVE-2018-19790]
https://symfony.com/blog/cve-2018-19790-open-redirect-vulnerability-wh
en-using-security-http

For Debian 8 'Jessie', these problems have been fixed in version
2.3.21+dfsg-4+deb8u4.

We recommend that you upgrade your symfony packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/symfony"
  );
  # https://symfony.com/blog/cve-2017-16652-open-redirect-vulnerability-on-security-handlers
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f99409b"
  );
  # https://symfony.com/blog/cve-2017-16654-intl-bundle-readers-breaking-out-of-paths
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7dce206"
  );
  # https://symfony.com/blog/cve-2018-11385-session-fixation-issue-for-guard-authentication
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a195ddf"
  );
  # https://symfony.com/blog/cve-2018-11408-open-redirect-vulnerability-on-security-handlers
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39450434"
  );
  # https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?391e80f4"
  );
  # https://symfony.com/blog/cve-2018-19789-disclosure-of-uploaded-files-full-path
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df081f61"
  );
  # https://symfony.com/blog/cve-2018-19790-open-redirect-vulnerability-when-using-security-http
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a01aecd"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");
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
if (deb_check(release:"8.0", prefix:"php-symfony-browser-kit", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-class-loader", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-classloader", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-config", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-console", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-css-selector", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-debug", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dependency-injection", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-doctrine-bridge", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dom-crawler", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-event-dispatcher", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-eventdispatcher", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-filesystem", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-finder", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-form", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-framework-bundle", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-foundation", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-kernel", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-intl", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-locale", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-monolog-bridge", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-options-resolver", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-process", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-propel1-bridge", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-property-access", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-proxy-manager-bridge", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-routing", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security-bundle", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-serializer", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-stopwatch", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-swiftmailer-bridge", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-templating", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-translation", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bridge", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bundle", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-validator", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-web-profiler-bundle", reference:"2.3.21+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-yaml", reference:"2.3.21+dfsg-4+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
