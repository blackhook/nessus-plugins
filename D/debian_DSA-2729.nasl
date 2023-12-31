#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2729. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69107);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-4134", "CVE-2013-4135");
  script_bugtraq_id(61438, 61439);
  script_xref(name:"DSA", value:"2729");

  script_name(english:"Debian DSA-2729-1 : openafs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenAFS, the implementation of the distributed filesystem AFS, has
been updated to no longer use DES for the encryption of tickets.
Additional migration steps are needed to fully set the update into
effect. For more information please see the upstream advisory:
OPENAFS-SA-2013-003

In addition the 'encrypt' option to the 'vos' tool was fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openafs.org/security/OPENAFS-SA-2013-003.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2013/dsa-2729"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.4.12.1+dfsg-4+squeeze2.

For the stable distribution (wheezy), these problems have been fixed
in version 1.6.1-3+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"libopenafs-dev", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpam-openafs-kaserver", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-client", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbg", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbserver", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-doc", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-fileserver", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-kpasswd", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-krb5", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-dkms", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-source", reference:"1.4.12.1+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"libafsauthent1", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libafsrpc1", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkopenafs1", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libopenafs-dev", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-openafs-kaserver", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-client", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbg", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbserver", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-doc", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fileserver", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fuse", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-kpasswd", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-krb5", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-dkms", reference:"1.6.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-source", reference:"1.6.1-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
