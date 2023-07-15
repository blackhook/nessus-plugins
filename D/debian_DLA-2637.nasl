#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2637-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(149015);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_name(english:"Debian DLA-2637-1 : drupal7 security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Drupal project identified a vulnerability in the sanitization
performed in the _filter_xss_arttributes function, potentially
allowing a cross-site scripting, and granted it the Drupal Security
Advisory ID SA-CORE-2021-002 :

https://www.drupal.org/sa-core-2021-002

No CVE number has been announced.

For Debian 9 'Stretch', the fix to this issue was backported in
version 7.52-2+deb9u15.

We recommend you upgrade your drupal7 package.

For detailed security status of drupal7, please refer to its security
tracker page :

https://security-tracker.debian.org/tracker/source-package/drupal7

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/drupal7"
  );
  # https://security-tracker.debian.org/tracker/source-package/source-package/drupal7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87fc5303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/sa-core-2021-002"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected drupal7 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:drupal7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"drupal7", reference:"7.52-2+deb9u15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
