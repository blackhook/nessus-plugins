#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4134. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107279);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-7738");
  script_xref(name:"DSA", value:"4134");

  script_name(english:"Debian DSA-4134-1 : util-linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bjorn Bosselmann discovered that the umount bash completion from
util-linux does not properly handle embedded shell commands in a
mountpoint name. An attacker with rights to mount filesystems can take
advantage of this flaw for privilege escalation if a user (in
particular root) is tricked into using the umount completion while a
specially crafted mount is present."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=892179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/util-linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/util-linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4134"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the util-linux packages.

For the stable distribution (stretch), this problem has been fixed in
version 2.29.2-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");
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
if (deb_check(release:"9.0", prefix:"bsdutils", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libblkid-dev", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libblkid1", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfdisk-dev", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfdisk1", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmount-dev", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmount1", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsmartcols-dev", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsmartcols1", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libuuid1", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mount", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"setpriv", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"util-linux", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"util-linux-locales", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"uuid-dev", reference:"2.29.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"uuid-runtime", reference:"2.29.2-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
