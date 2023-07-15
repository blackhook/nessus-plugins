#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4179. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109329);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_xref(name:"DSA", value:"4179");

  script_name(english:"Debian DSA-4179-1 : linux-tools - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update doesn't fix a vulnerability in linux-tools, but provides
support for building Linux kernel modules with the
'retpoline'mitigation for CVE-2017-5715 (Spectre variant 2).

This update also includes bug fixes from the upstream Linux 3.16
stable branch up to and including 3.16.56."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux-tools"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux-tools"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-tools packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 3.16.56-1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"hyperv-daemons", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"libusbip-dev", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-kbuild-3.16", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-tools-3.16", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"usbip", reference:"3.16.56-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
