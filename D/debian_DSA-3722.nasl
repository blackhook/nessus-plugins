#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3722. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95264);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-1248");
  script_xref(name:"DSA", value:"3722");

  script_name(english:"Debian DSA-3722-1 : vim - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Larysch and Bram Moolenaar discovered that vim, an enhanced vi
editor, does not properly validate values for the 'filetype','syntax'
and 'keymap' options, which may result in the execution of arbitrary
code if a file with a specially crafted modeline is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/vim"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3722"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vim packages.

For the stable distribution (jessie), this problem has been fixed in
version 2:7.4.488-7+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"vim", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-athena", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-common", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-dbg", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-doc", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gnome", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gtk", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gui-common", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-lesstif", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-nox", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-runtime", reference:"2:7.4.488-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-tiny", reference:"2:7.4.488-7+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
