#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2429-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142504);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2020-28032", "CVE-2020-28033", "CVE-2020-28034", "CVE-2020-28035", "CVE-2020-28036", "CVE-2020-28037", "CVE-2020-28038", "CVE-2020-28039", "CVE-2020-28040");

  script_name(english:"Debian DLA-2429-1 : wordpress security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There were several vulnerabilites reported against wordpress, as
follows :

CVE-2020-28032

WordPress before 4.7.19 mishandles deserialization requests in
wp-includes/Requests/Utility/FilteredIterator.php.

CVE-2020-28033

WordPress before 4.7.19 mishandles embeds from disabled sites on a
multisite network, as demonstrated by allowing a spam embed.

CVE-2020-28034

WordPress before 4.7.19 allows XSS associated with global variables.

CVE-2020-28035

WordPress before 4.7.19 allows attackers to gain privileges via
XML-RPC.

CVE-2020-28036

wp-includes/class-wp-xmlrpc-server.php in WordPress before 4.7.19
allows attackers to gain privileges by using XML-RPC to comment on a
post.

CVE-2020-28037

is_blog_installed in wp-includes/functions.php in WordPress before
4.7.19 improperly determines whether WordPress is already installed,
which might allow an attacker to perform a new installation, leading
to remote code execution (as well as a denial of service for the old
installation).

CVE-2020-28038

WordPress before 4.7.19 allows stored XSS via post slugs.

CVE-2020-28039

is_protected_meta in wp-includes/meta.php in WordPress before 4.7.19
allows arbitrary file deletion because it does not properly determine
whether a meta key is considered protected.

CVE-2020-28040

WordPress before 4.7.19 allows CSRF attacks that change a theme's
background image.

For Debian 9 stretch, these problems have been fixed in version
4.7.19+dfsg-1+deb9u1.

We recommend that you upgrade your wordpress packages.

For the detailed security status of wordpress please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/wordpress

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wordpress"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28037");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyfifteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyseventeen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentysixteen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"wordpress", reference:"4.7.19+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-l10n", reference:"4.7.19+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.7.19+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyseventeen", reference:"4.7.19+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentysixteen", reference:"4.7.19+dfsg-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
