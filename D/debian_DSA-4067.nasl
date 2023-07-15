#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4067. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105331);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-17432");
  script_xref(name:"DSA", value:"4067");

  script_name(english:"Debian DSA-4067-1 : openafs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that malformed jumbogram packets could result in
denial of service against OpenAFS, an implementation of the Andrew
distributed file system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4067"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.6.9-2+deb8u6. This update also provides corrections for
CVE-2016-4536 and CVE-2016-9772.

For the stable distribution (stretch), this problem has been fixed in
version 1.6.20-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");
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
if (deb_check(release:"8.0", prefix:"libafsauthent1", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libafsrpc1", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libkopenafs1", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenafs-dev", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-openafs-kaserver", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-client", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbg", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbserver", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-doc", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fileserver", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fuse", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-kpasswd", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-krb5", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-dkms", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-source", reference:"1.6.9-2+deb8u6")) flag++;
if (deb_check(release:"9.0", prefix:"libafsauthent1", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libafsrpc1", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkopenafs1", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libopenafs-dev", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-openafs-kaserver", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-client", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-dbserver", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-doc", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-fileserver", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-fuse", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-kpasswd", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-krb5", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-modules-dkms", reference:"1.6.20-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-modules-source", reference:"1.6.20-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
