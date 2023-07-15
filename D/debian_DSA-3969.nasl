#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3969. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103146);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915", "CVE-2017-10916", "CVE-2017-10917", "CVE-2017-10918", "CVE-2017-10919", "CVE-2017-10920", "CVE-2017-10921", "CVE-2017-10922", "CVE-2017-12135", "CVE-2017-12136", "CVE-2017-12137", "CVE-2017-12855", "CVE-2017-15596");
  script_xref(name:"DSA", value:"3969");

  script_name(english:"Debian DSA-3969-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor :

  - CVE-2017-10912
    Jann Horn discovered that incorrectly handling of page
    transfers might result in privilege escalation.

  - CVE-2017-10913 / CVE-2017-10914
    Jann Horn discovered that race conditions in grant
    handling might result in information leaks or privilege
    escalation.

  - CVE-2017-10915
    Andrew Cooper discovered that incorrect reference
    counting with shadow paging might result in privilege
    escalation.

  - CVE-2017-10916
    Andrew Cooper discovered an information leak in the
    handling of the Memory Protection Extensions (MPX) and
    Protection Key (PKU) CPU features. This only affects
    Debian stretch.

  - CVE-2017-10917
    Ankur Arora discovered a NULL pointer dereference in
    event polling, resulting in denial of service.

  - CVE-2017-10918
    Julien Grall discovered that incorrect error handling in
    physical-to-machine memory mappings may result in
    privilege escalation, denial of service or an
    information leak.

  - CVE-2017-10919
    Julien Grall discovered that incorrect handling of
    virtual interrupt injection on ARM systems may result in
    denial of service.

  - CVE-2017-10920 / CVE-2017-10921 / CVE-2017-10922
    Jan Beulich discovered multiple places where reference
    counting on grant table operations was incorrect,
    resulting in potential privilege escalation.

  - CVE-2017-12135
    Jan Beulich found multiple problems in the handling of
    transitive grants which could result in denial of
    service and potentially privilege escalation.

  - CVE-2017-12136
    Ian Jackson discovered that race conditions in the
    allocator for grant mappings may result in denial of
    service or privilege escalation. This only affects
    Debian stretch.

  - CVE-2017-12137
    Andrew Cooper discovered that incorrect validation of
    grants may result in privilege escalation.

  - CVE-2017-12855
    Jan Beulich discovered that incorrect grant status
    handling, thus incorrectly informing the guest that the
    grant is no longer in use.

  - XSA-235 (no CVE yet)

    Wei Liu discovered that incorrect locking of
    add-to-physmap operations on ARM may result in denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3969"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 4.4.1-9+deb8u10.

For the stable distribution (stretch), these problems have been fixed
in version 4.8.1-1+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
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
if (deb_check(release:"8.0", prefix:"libxen-4.4", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libxen-dev", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libxenstore3.0", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-amd64", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-arm64", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-armhf", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-amd64", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-arm64", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-armhf", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-4.4", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-common", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"xenstore-utils", reference:"4.4.1-9+deb8u10")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.1-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
