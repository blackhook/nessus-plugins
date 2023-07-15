#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4339. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118939);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2017-7519", "CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129");
  script_xref(name:"DSA", value:"4339");

  script_name(english:"Debian DSA-4339-1 : ceph - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities were discovered in Ceph, a distributed
storage and file system: The cephx authentication protocol was
suspectible to replay attacks and calculated signatures incorrectly,
'ceph mon' did not validate capabilities for pool operations
(resulting in potential corruption or deletion of snapshot images) and
a format string vulnerability in libradosstriper could result in
denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ceph"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ceph"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4339"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the ceph packages.

For the stable distribution (stretch), these problems have been fixed
in version 10.2.11-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"ceph", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-base", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-common", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-fs-common", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-fuse", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-mds", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-mon", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-osd", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-resource-agents", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"ceph-test", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcephfs-dev", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcephfs-java", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcephfs-jni", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcephfs1", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"librados-dev", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"librados2", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"libradosstriper-dev", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"libradosstriper1", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"librbd-dev", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"librbd1", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"librgw-dev", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"librgw2", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"python-ceph", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"python-cephfs", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"python-rados", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"python-rbd", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"radosgw", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"rbd-fuse", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"rbd-mirror", reference:"10.2.11-1")) flag++;
if (deb_check(release:"9.0", prefix:"rbd-nbd", reference:"10.2.11-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
