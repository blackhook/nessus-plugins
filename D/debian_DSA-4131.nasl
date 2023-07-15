#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4131. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107123);
  script_version("3.4");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-7540", "CVE-2018-7541", "CVE-2018-7542");
  script_xref(name:"DSA", value:"4131");

  script_name(english:"Debian DSA-4131-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor :

  - CVE-2018-7540
    Jann Horn discovered that missing checks in page table
    freeing may result in denial of service.

  - CVE-2018-7541
    Jan Beulich discovered that incorrect error handling in
    grant table checks may result in guest-to-host denial of
    service and potentially privilege escalation.

  - CVE-2018-7542
    Ian Jackson discovered that insufficient handling of x86
    PVH guests without local APICs may result in
    guest-to-host denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4131"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.8.3+comet2+shim4.10.0+comet3-1+deb9u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/05");
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
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
