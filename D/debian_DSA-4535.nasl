#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4535. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129413);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/23");

  script_cve_id("CVE-2019-5094");
  script_xref(name:"DSA", value:"4535");

  script_name(english:"Debian DSA-4535-1 : e2fsprogs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Lilith of Cisco Talos discovered a buffer overflow flaw in the quota
code used by e2fsck from the ext2/ext3/ext4 file system utilities.
Running e2fsck on a malformed file system can result in the execution
of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=941139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/e2fsprogs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/e2fsprogs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/e2fsprogs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4535"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the e2fsprogs packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 1.43.4-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 1.44.5-1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"comerr-dev", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"e2fsck-static", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"e2fslibs", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"e2fslibs-dev", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"e2fsprogs", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"e2fsprogs-l10n", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"e2fsprogs-udeb", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse2fs", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcom-err2", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcomerr2", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libext2fs-dev", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libext2fs2", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libss2", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ss-dev", reference:"1.44.5-1+deb10u2")) flag++;
if (deb_check(release:"9.0", prefix:"comerr-dev", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"e2fsck-static", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"e2fslibs", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"e2fslibs-dev", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"e2fsprogs", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"e2fsprogs-udeb", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"fuse2fs", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcomerr2", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libss2", reference:"1.43.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ss-dev", reference:"1.43.4-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
