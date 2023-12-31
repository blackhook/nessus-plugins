#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2337. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56716);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-1166", "CVE-2011-1583", "CVE-2011-1898", "CVE-2011-3262");
  script_bugtraq_id(47779, 48058, 48515);
  script_xref(name:"DSA", value:"2337");

  script_name(english:"Debian DSA-2337-1 : xen - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Xen virtual machine
hypervisor.

  - CVE-2011-1166
    A 64-bit guest can get one of its vCPUs into non-kernel
    mode without first providing a valid non-kernel
    pagetable, thereby locking up the host system.

  - CVE-2011-1583, CVE-2011-3262
    Local users can cause a denial of service and possibly
    execute arbitrary code via a crafted paravirtualised
    guest kernel image.

  - CVE-2011-1898
    When using PCI passthrough on Intel VT-d chipsets that
    do not have interrupt remapping, guest OS users can gain
    host OS privileges by writing to the interrupt injection
    registers.

The oldstable distribution (lenny) contains a different version of Xen
not affected by these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2337"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.1-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"libxen-dev", reference:"4.0.1-4")) flag++;
if (deb_check(release:"6.0", prefix:"libxenstore3.0", reference:"4.0.1-4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-docs-4.0", reference:"4.0.1-4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-amd64", reference:"4.0.1-4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-i386", reference:"4.0.1-4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-utils-4.0", reference:"4.0.1-4")) flag++;
if (deb_check(release:"6.0", prefix:"xenstore-utils", reference:"4.0.1-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
