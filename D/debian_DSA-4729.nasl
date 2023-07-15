#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4729. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138649);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/03");

  script_cve_id("CVE-2019-14380", "CVE-2019-17113");
  script_xref(name:"DSA", value:"4729");

  script_name(english:"Debian DSA-4729-1 : libopenmpt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two security issues were found in libopenmpt, a cross-platform C++ and
C library to decode tracked music files, which could result in denial
of service and potentially the execution of arbitrary code if
malformed music files are processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libopenmpt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/libopenmpt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4729"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the libopenmpt packages.

For the stable distribution (buster), these problems have been fixed
in version 0.4.3-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenmpt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libopenmpt-dev", reference:"0.4.3-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libopenmpt-doc", reference:"0.4.3-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libopenmpt-modplug-dev", reference:"0.4.3-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libopenmpt-modplug1", reference:"0.4.3-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libopenmpt0", reference:"0.4.3-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openmpt123", reference:"0.4.3-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
