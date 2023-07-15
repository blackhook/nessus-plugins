#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1565-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118733);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-14651", "CVE-2018-14652", "CVE-2018-14653", "CVE-2018-14659", "CVE-2018-14661");

  script_name(english:"Debian DLA-1565-1 : glusterfs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security vulnerabilities were discovered in GlusterFS, a
clustered file system. Buffer overflows and path traversal issues may
lead to information disclosure, denial of service or the execution of
arbitrary code.

CVE-2018-14651

It was found that the fix for CVE-2018-10927, CVE-2018-10928,
CVE-2018-10929, CVE-2018-10930, and CVE-2018-10926 was incomplete. A
remote, authenticated attacker could use one of these flaws to execute
arbitrary code, create arbitrary files, or cause denial of service on
glusterfs server nodes via symlinks to relative paths.

CVE-2018-14652

The Gluster file system is vulnerable to a buffer overflow in the
'features/index' translator via the code handling the
'GF_XATTR_CLRLK_CMD' xattr in the 'pl_getxattr' function. A remote
authenticated attacker could exploit this on a mounted volume to cause
a denial of service.

CVE-2018-14653

The Gluster file system is vulnerable to a heap-based buffer overflow
in the '__server_getspec' function via the 'gf_getspec_req' RPC
message. A remote authenticated attacker could exploit this to cause a
denial of service or other potential unspecified impact.

CVE-2018-14659

The Gluster file system is vulnerable to a denial of service attack
via use of the 'GF_XATTR_IOSTATS_DUMP_KEY' xattr. A remote,
authenticated attacker could exploit this by mounting a Gluster volume
and repeatedly calling 'setxattr(2)' to trigger a state dump and
create an arbitrary number of files in the server's runtime directory.

CVE-2018-14661

It was found that usage of snprintf function in feature/locks
translator of glusterfs server was vulnerable to a format string
attack. A remote, authenticated attacker could use this flaw to cause
remote denial of service.

For Debian 8 'Jessie', these problems have been fixed in version
3.5.2-2+deb8u5.

We recommend that you upgrade your glusterfs packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/glusterfs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/06");
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
if (deb_check(release:"8.0", prefix:"glusterfs-client", reference:"3.5.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"glusterfs-common", reference:"3.5.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"glusterfs-dbg", reference:"3.5.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"glusterfs-server", reference:"3.5.2-2+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
