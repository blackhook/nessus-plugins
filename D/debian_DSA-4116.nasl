#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4116. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106874);
  script_version("3.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-6791");
  script_xref(name:"DSA", value:"4116");

  script_name(english:"Debian DSA-4116-1 : plasma-workspace - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Krzysztof Sieluzycki discovered that the notifier for removable
devices in the KDE Plasma workspace performed insufficient
sanitisation of FAT/VFAT volume labels, which could result in the
execution of arbitrary shell commands if a removable device with a
malformed disk label is mounted."
  );
  # https://security-tracker.debian.org/tracker/source-package/plasma-workspace
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1dd18931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/plasma-workspace"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4116"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the plasma-workspace packages.

For the stable distribution (stretch), this problem has been fixed in
version 4:5.8.6-2.1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:plasma-workspace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
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
if (deb_check(release:"9.0", prefix:"libkworkspace5-5", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libplasma-geolocation-interface5", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtaskmanager6", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libweather-ion7", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"plasma-workspace", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"plasma-workspace-dev", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"plasma-workspace-wayland", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"sddm-theme-breeze", reference:"4:5.8.6-2.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"sddm-theme-debian-breeze", reference:"4:5.8.6-2.1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
