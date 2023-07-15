#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2484-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143597);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/09");

  script_name(english:"Debian DLA-2484-1 : python-certbot - switch to ACMEv2 API");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Let's Encrypt's ACMEv1 API is deprecated and in the process of being
shut down. Beginning with brownouts in January 2021, and ending with a
total shutdown in June 2021, the Let's Encrypt APIs will become
unavailable. To prevent users having disruptions to their certificate
renewals, this update backports the switch over to the ACMEv2 API.

For Debian 9 stretch, this problem has been fixed in version
0.28.0-1~deb9u3.

We recommend that you upgrade your python-certbot packages.

For the detailed security status of python-certbot please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python-certbot

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-certbot"
  );
  # https://security-tracker.debian.org/tracker/source-package/python-certbot
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4385dfd9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:certbot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:letsencrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-certbot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-certbot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
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
if (deb_check(release:"9.0", prefix:"certbot", reference:"0.28.0-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"letsencrypt", reference:"0.28.0-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-certbot-doc", reference:"0.28.0-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python3-certbot", reference:"0.28.0-1~deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
