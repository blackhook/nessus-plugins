#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1427-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111085);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1427-1 : znc security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there were two issues in znc, a modular IRC
bouncer :

  - There was insufficient validation of lines coming from
    the network allowing a non-admin user to escalate his
    privilege and inject rogue values into znc.conf.
    (CVE-2018-14055)

  - A path traversal vulnerability (via '../' being embedded
    in a web skin name) to access files outside of the
    allowed directory. (CVE-2018-14056)

For Debian 8 'Jessie', these issues have been fixed in znc version
1.4-2+deb8u1.

We recommend that you upgrade your znc packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/znc"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:znc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:znc-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:znc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:znc-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:znc-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:znc-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"znc", reference:"1.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"znc-dbg", reference:"1.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"znc-dev", reference:"1.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"znc-perl", reference:"1.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"znc-python", reference:"1.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"znc-tcl", reference:"1.4-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
