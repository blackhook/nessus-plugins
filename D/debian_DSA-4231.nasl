#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4231. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110572);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-0495");
  script_xref(name:"DSA", value:"4231");

  script_name(english:"Debian DSA-4231-1 : libgcrypt20 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Libgcrypt is prone to a local side-channel
attack allowing recovery of ECDSA private keys."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libgcrypt20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libgcrypt20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4231"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgcrypt20 packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.7.6-2+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/18");
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
if (deb_check(release:"9.0", prefix:"libgcrypt-mingw-w64-dev", reference:"1.7.6-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt11-dev", reference:"1.7.6-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20", reference:"1.7.6-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-dev", reference:"1.7.6-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-doc", reference:"1.7.6-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-udeb", reference:"1.7.6-2+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
