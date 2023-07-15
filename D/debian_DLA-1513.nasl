#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1513-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117640);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949");

  script_name(english:"Debian DLA-1513-1 : openafs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were discovered in OpenAFS, a
distributed file system.

CVE-2018-16947

The backup tape controller process accepts incoming RPCs but does not
require (or allow for) authentication of those RPCs. Handling those
RPCs results in operations being performed with administrator
credentials, including dumping/restoring volume contents and
manipulating the backup database.

CVE-2018-16948

Several RPC server routines did not fully initialize their output
variables before returning, leaking memory contents from both the
stack and the heap. Because the OpenAFS cache manager functions as an
Rx server for the AFSCB service, clients are also susceptible to
information leakage.

CVE-2018-16949

Several data types used as RPC input variables were implemented as
unbounded array types, limited only by the inherent 32-bit length
field to 4GB. An unauthenticated attacker could send, or claim to
send, large input values and consume server resources waiting for
those inputs, denying service to other valid connections.

For Debian 8 'Jessie', these problems have been fixed in version
1.6.9-2+deb8u8.

We recommend that you upgrade your openafs packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openafs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libafsauthent1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libafsrpc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkopenafs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenafs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-openafs-kaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-dbserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-fileserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-modules-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-modules-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");
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
if (deb_check(release:"8.0", prefix:"libafsauthent1", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libafsrpc1", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libkopenafs1", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libopenafs-dev", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-openafs-kaserver", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-client", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbg", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbserver", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-doc", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fileserver", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fuse", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-kpasswd", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-krb5", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-dkms", reference:"1.6.9-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-source", reference:"1.6.9-2+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
