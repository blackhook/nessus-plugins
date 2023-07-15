#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4302. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117675);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/20 11:04:16");

  script_cve_id("CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949");
  script_xref(name:"DSA", value:"4302");

  script_name(english:"Debian DSA-4302-1 : openafs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in openafs, an implementation
of the distributed filesystem AFS. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2018-16947
    Jeffrey Altman reported that the backup tape controller
    (butc) process does accept incoming RPCs but does not
    require (or allow for) authentication of those RPCs,
    allowing an unauthenticated attacker to perform volume
    operations with administrator credentials.

  - CVE-2018-16948
    Mark Vitale reported that several RPC server routines do
    not fully initialize output variables, leaking memory
    contents (from both the stack and the heap) to the
    remote caller for otherwise-successful RPCs.

  - CVE-2018-16949
    Mark Vitale reported that an unauthenticated attacker
    can consume large amounts of server memory and network
    bandwidth via specially crafted requests, resulting in
    denial of service to legitimate clients."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=908616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4302"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the stable distribution (stretch), these problems have been fixed
in version 1.6.20-2+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
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
if (deb_check(release:"9.0", prefix:"libafsauthent1", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libafsrpc1", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libkopenafs1", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libopenafs-dev", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-openafs-kaserver", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-client", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-dbserver", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-doc", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-fileserver", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-fuse", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-kpasswd", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-krb5", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-modules-dkms", reference:"1.6.20-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openafs-modules-source", reference:"1.6.20-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
