#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-93-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82238);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-5270");
  script_bugtraq_id(69164);

  script_name(english:"Debian DLA-93-1 : libgcrypt11 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel Genkin, Itamar Pipman and Eran Tromer discovered that Elgamal
encryption subkeys in applications using the libgcrypt11 library, for
example GnuPG 2.x, could be leaked via a side-channel attack (see
http://www.cs.tau.ac.il/~tromer/handsoff/).

This is fixed in Squeeze in version 1.4.5-2+squeeze2.

We recommend that you upgrade your libgcrypt11 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cs.tau.ac.il/~tromer/handsoff/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/11/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libgcrypt11"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"libgcrypt11", reference:"1.4.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgcrypt11-dbg", reference:"1.4.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgcrypt11-dev", reference:"1.4.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgcrypt11-doc", reference:"1.4.5-2+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
