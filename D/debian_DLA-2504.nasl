#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2504-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144574);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-15005", "CVE-2020-35477", "CVE-2020-35479", "CVE-2020-35480");

  script_name(english:"Debian DLA-2504-1 : mediawiki security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in MediaWiki, a website
engine for collaborative work.

CVE-2020-15005

Private wikis behind a caching server using the img_auth.php image
authorization security feature may have had their files cached
publicly, so any unauthorized user could view them.

CVE-2020-35477

Blocks legitimate attempts to hide log entries in some situations.

CVE-2020-35479

Allows XSS via BlockLogFormatter.php. Language::translateBlockExpiry
itself does not escape in all code paths. For example, the return of
Language::userTimeAndDate is is always unsafe for HTML in a month
value.

CVE-2020-35480

Missing users (accounts that don't exist) and hidden users (accounts
that have been explicitly hidden due to being abusive, or similar)
that the viewer cannot see are handled differently, exposing sensitive
information about the hidden status to unprivileged viewers.

For Debian 9 stretch, these problems have been fixed in version
1:1.27.7-1~deb9u7.

We recommend that you upgrade your mediawiki packages.

For the detailed security status of mediawiki please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/mediawiki

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/mediawiki"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/mediawiki"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected mediawiki, and mediawiki-classes packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35480");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki-classes");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"mediawiki", reference:"1:1.27.7-1~deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"mediawiki-classes", reference:"1:1.27.7-1~deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
