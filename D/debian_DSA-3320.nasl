#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3320. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85129);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-3282", "CVE-2015-3283", "CVE-2015-3284", "CVE-2015-3285", "CVE-2015-6587");
  script_xref(name:"DSA", value:"3320");

  script_name(english:"Debian DSA-3320-1 : openafs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that OpenAFS, the implementation of the distributed
filesystem AFS, contained several flaws that could result in
information leak, denial-of-service or kernel panic."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3320"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.6.1-3+deb7u3.

For the stable distribution (jessie), these problems have been fixed
in version 1.6.9-2+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libafsauthent1", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libafsrpc1", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkopenafs1", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libopenafs-dev", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-openafs-kaserver", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-client", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbg", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbserver", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-doc", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fileserver", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fuse", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-kpasswd", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-krb5", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-dkms", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-source", reference:"1.6.1-3+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"libafsauthent1", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libafsrpc1", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libkopenafs1", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libopenafs-dev", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-openafs-kaserver", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-client", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbg", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbserver", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-doc", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fileserver", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fuse", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-kpasswd", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-krb5", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-dkms", reference:"1.6.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-source", reference:"1.6.9-2+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
