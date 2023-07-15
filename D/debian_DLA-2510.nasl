#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2510-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144638);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/30");

  script_name(english:"Debian DLA-2510-1 : libdatetime-timezone-perl new upstream release");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update includes the changes in tzdata 2020e for the Perl
bindings. For the list of changes, see DLA-2510-1.

For Debian 9 stretch, this problem has been fixed in version
1:2.09-1+2020e.

We recommend that you upgrade your libdatetime-time zone-perl packages.

For the detailed security status of libdatetime-time zone-perl please
refer to its security tracker page at:
https://security-tracker.debian.org/tracker/libdatetime-time zone-perl

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libdatetime-timezone-perl"
  );
  # https://security-tracker.debian.org/tracker/source-package/libdatetime-timezone-perl
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e4a1426"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected libdatetime-timezone-perl package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdatetime-timezone-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/30");
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
if (deb_check(release:"9.0", prefix:"libdatetime-timezone-perl", reference:"1:2.09-1+2020e")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
