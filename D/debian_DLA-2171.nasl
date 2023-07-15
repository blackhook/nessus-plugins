#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2171-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135364);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-1760");

  script_name(english:"Debian DLA-2171-1 : ceph security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a header-splitting vulnerability in
ceph, a distributed storage and file system.

For Debian 8 'Jessie', this issue has been fixed in ceph version
0.80.7-2+deb8u4.

We recommend that you upgrade your ceph packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/04/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ceph"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1760");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-common-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fs-common-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fuse-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mds-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-test-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-jni-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radosgw-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-fuse-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rest-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rest-bench-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"ceph", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-common", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-common-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-fs-common", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-fs-common-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-fuse", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-fuse-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-mds", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-mds-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-resource-agents", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-test", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ceph-test-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcephfs-dev", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcephfs-java", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcephfs-jni", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcephfs-jni-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcephfs1", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcephfs1-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"librados-dev", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"librados2", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"librados2-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"librbd-dev", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"librbd1", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"librbd1-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-ceph", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"radosgw", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"radosgw-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"rbd-fuse", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"rbd-fuse-dbg", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"rest-bench", reference:"0.80.7-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"rest-bench-dbg", reference:"0.80.7-2+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
