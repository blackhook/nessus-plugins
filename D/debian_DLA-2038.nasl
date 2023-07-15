#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2038-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132105);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-2038-2 : x2goclient regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A change introduced in libssh 0.6.3-4+deb8u4 (which got released as
DLA 2038-1) has broken x2goclient's way of scp'ing session setup files
from client to server, resulting in an error message shown in a GUI
error dialog box during session startup (and session resuming).

For Debian 8 'Jessie', this problem has been fixed in x2goclient
version 4.0.3.1-4+deb8u1.

We recommend that you upgrade your x2goclient packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/x2goclient"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:x2goclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:x2goclient-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:x2goplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:x2goplugin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:x2goplugin-provider");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");
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
if (deb_check(release:"8.0", prefix:"x2goclient", reference:"4.0.3.1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"x2goclient-dbg", reference:"4.0.3.1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"x2goplugin", reference:"4.0.3.1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"x2goplugin-dbg", reference:"4.0.3.1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"x2goplugin-provider", reference:"4.0.3.1-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
