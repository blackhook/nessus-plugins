#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2269-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138062);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-4046", "CVE-2020-4047", "CVE-2020-4048", "CVE-2020-4049", "CVE-2020-4050");

  script_name(english:"Debian DLA-2269-1 : wordpress security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in Wordpress, a web blogging
tool. They allowed remote attackers to perform various Cross-Side
Scripting (XSS) attacks, create open redirects, escalate privileges,
and bypass authorization access.

CVE-2020-4046

In affected versions of WordPress, users with low privileges (like
contributors and authors) can use the embed block in a certain way to
inject unfiltered HTML in the block editor. When affected posts are
viewed by a higher privileged user, this could lead to script
execution in the editor/wp-admin.

CVE-2020-4047

In affected versions of WordPress, authenticated users with upload
permissions (like authors) are able to inject JavaScript into some
media file attachment pages in a certain way. This can lead to script
execution in the context of a higher privileged user when the file is
viewed by them.

CVE-2020-4048

In affected versions of WordPress, due to an issue in
wp_validate_redirect() and URL sanitization, an arbitrary external
link can be crafted leading to unintended/open redirect when clicked.

CVE-2020-4049

In affected versions of WordPress, when uploading themes, the name of
the theme folder can be crafted in a way that could lead to JavaScript
execution in /wp-admin on the themes page. This does require an admin
to upload the theme, and is low severity self-XSS.

CVE-2020-4050

In affected versions of WordPress, misuse of the `set-screen-option`
filter's return value allows arbitrary user meta fields to be saved.
It does require an admin to install a plugin that would misuse the
filter. Once installed, it can be leveraged by low privileged users.

For Debian 8 'Jessie', these problems have been fixed in version
4.1.31+dfsg-0+deb8u1.

We recommend that you upgrade your wordpress packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wordpress"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4050");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyfifteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyfourteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentythirteen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"wordpress", reference:"4.1.31+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-l10n", reference:"4.1.31+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.1.31+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfourteen", reference:"4.1.31+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentythirteen", reference:"4.1.31+dfsg-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
