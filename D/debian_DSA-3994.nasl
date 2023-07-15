#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3994. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103717);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14604");
  script_xref(name:"DSA", value:"3994");

  script_name(english:"Debian DSA-3994-1 : nautilus - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Boxdorfer discovered a vulnerability in the handling of
FreeDesktop.org .desktop files in Nautilus, a file manager for the
GNOME desktop environment. An attacker can craft a .desktop file
intended to run malicious commands but displayed as a innocuous
document file in Nautilus. An user would then trust it and open the
file, and Nautilus would in turn execute the malicious content.
Nautilus protection of only trusting .desktop files with executable
permission can be bypassed by shipping the .desktop file inside a
tarball."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=860268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/nautilus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3994"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nautilus packages.

For the oldstable distribution (jessie), this problem has not been
fixed yet.

For the stable distribution (stretch), this problem has been fixed in
version 3.22.3-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"gir1.2-nautilus-3.0", reference:"3.22.3-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libnautilus-extension-dev", reference:"3.22.3-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libnautilus-extension1a", reference:"3.22.3-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nautilus", reference:"3.22.3-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nautilus-data", reference:"3.22.3-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
