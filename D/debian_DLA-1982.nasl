#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1982-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130523);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-18601", "CVE-2019-18602", "CVE-2019-18603");

  script_name(english:"Debian DLA-1982-1 : openafs security update");
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

CVE-2019-18601

OpenAFS is prone to denial of service from unserialized data access
because remote attackers can make a series of VOTE_Debug RPC calls to
crash a database server within the SVOTE_Debug RPC handler.

CVE-2019-18602

OpenAFS is prone to an information disclosure vulnerability because
uninitialized scalars are sent over the network to a peer.

CVE-2019-18603

OpenAFS is prone to information leakage upon certain error conditions
because uninitialized RPC output variables are sent over the network
to a peer.

For Debian 8 'Jessie', these problems have been fixed in version
1.6.9-2+deb8u9.

We recommend that you upgrade your openafs packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openafs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18602");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libafsauthent1", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libafsrpc1", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libkopenafs1", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libopenafs-dev", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-openafs-kaserver", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-client", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbg", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbserver", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-doc", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fileserver", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fuse", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-kpasswd", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-krb5", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-dkms", reference:"1.6.9-2+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-source", reference:"1.6.9-2+deb8u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
