#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-263-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84494);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-5371", "CVE-2013-0269");
  script_bugtraq_id(56484, 57899);

  script_name(english:"Debian DLA-263-1 : ruby1.9.1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were identified in the Ruby language interpreter,
version 1.9.1.

CVE-2012-5371

Jean-Philippe Aumasson identified that Ruby computed hash values
without properly restricting the ability to trigger hash collisions
predictably, allowing context-dependent attackers to cause a denial of
service (CPU consumption). This is a different vulnerability than
CVE-2011-4815.

CVE-2013-0269

Thomas Hollstegge and Ben Murphy found that the JSON gem for Ruby
allowed remote attackers to cause a denial of service (resource
consumption) or bypass the mass assignment protection mechanism via a
crafted JSON document that triggers the creation of arbitrary Ruby
symbols or certain internal objects.

For the squeeze distribution, theses vulnerabilities have been fixed
in version 1.9.2.0-2+deb6u5 of ruby1.9.1. We recommend that you
upgrade your ruby1.9.1 package.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ruby1.9.1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.9.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtcltk-ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ri1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-full");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libruby1.9.1", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libruby1.9.1-dbg", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libtcltk-ruby1.9.1", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"ri1.9.1", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-dev", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-elisp", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-examples", reference:"1.9.2.0-2+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-full", reference:"1.9.2.0-2+deb6u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
