#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2599-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(147901);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_name(english:"Debian DLA-2599-1 : shibboleth-sp2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Toni Huttunen discovered that the Shibboleth service provider's
template engine used to render error pages could be abused for
phishing attacks.

For additional information please refer to the upstream advisory at
https://shibboleth.net/community/advisories/secadv_20210317.txt

For Debian 9 stretch, this problem has been fixed in version
2.6.0+dfsg1-4+deb9u2.

We recommend that you upgrade your shibboleth-sp2 packages.

For the detailed security status of shibboleth-sp2 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/shibboleth-sp2

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/shibboleth-sp2"
  );
  # https://security-tracker.debian.org/tracker/source-package/shibboleth-sp2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f5dd291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://shibboleth.net/community/advisories/secadv_20210317.txt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-shib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libshibsp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libshibsp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libshibsp-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libshibsp7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:shibboleth-sp2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:shibboleth-sp2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");
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
if (deb_check(release:"9.0", prefix:"libapache2-mod-shib2", reference:"2.6.0+dfsg1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libshibsp-dev", reference:"2.6.0+dfsg1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libshibsp-doc", reference:"2.6.0+dfsg1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libshibsp-plugins", reference:"2.6.0+dfsg1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libshibsp7", reference:"2.6.0+dfsg1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"shibboleth-sp2-common", reference:"2.6.0+dfsg1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"shibboleth-sp2-utils", reference:"2.6.0+dfsg1-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
