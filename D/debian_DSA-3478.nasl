#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3478. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88741);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-7511");
  script_xref(name:"DSA", value:"3478");

  script_name(english:"Debian DSA-3478-1 : libgcrypt11 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel Genkin, Lev Pachmanov, Itamar Pipman and Eran Tromer discovered
that the ECDH secret decryption keys in applications using the
libgcrypt11 library could be leaked via a side-channel attack.

See https://www.cs.tau.ac.IL/~tromer/ecdh/ for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.cs.tau.ac.IL/~tromer/ecdh/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgcrypt11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3478"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgcrypt11 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.5.0-5+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");
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
if (deb_check(release:"7.0", prefix:"libgcrypt11", reference:"1.5.0-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-dbg", reference:"1.5.0-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-dev", reference:"1.5.0-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-doc", reference:"1.5.0-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-udeb", reference:"1.5.0-5+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
