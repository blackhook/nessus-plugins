#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-481. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15318);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
  script_bugtraq_id(10152);
  script_xref(name:"DSA", value:"481");

  script_name(english:"Debian DSA-481-1 : linux-kernel-2.4.17-ia64 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several serious problems have been discovered in the Linux kernel.
This update takes care of Linux 2.4.17 for the IA-64 architecture. The
Common Vulnerabilities and Exposures project identifies the following
problems that will be fixed with this update :

  - CAN-2004-0003
    A vulnerability has been discovered in the R128 DRI
    driver in the Linux kernel which could potentially lead
    an attacker to gain unauthorised privileges. Alan Cox
    and Thomas Biege developed a correction for this.

  - CAN-2004-0010

    Arjan van de Ven discovered a stack-based buffer
    overflow in the ncp_lookup function for ncpfs in the
    Linux kernel, which could lead an attacker to gain
    unauthorised privileges. Petr Vandrovec developed a
    correction for this.

  - CAN-2004-0109

    zen-parse discovered a buffer overflow vulnerability in
    the ISO9660 filesystem component of Linux kernel which
    could be abused by an attacker to gain unauthorised root
    access. Sebastian Krahmer and Ernie Petrides developed a
    correction for this.

  - CAN-2004-0177

    Solar Designer discovered an information leak in the
    ext3 code of Linux. In a worst case an attacker could
    read sensitive data such as cryptographic keys which
    would otherwise never hit disk media. Theodore Ts'o
    developed a correction for this.

  - CAN-2004-0178

    Andreas Kies discovered a denial of service condition in
    the Sound Blaster driver in Linux. He also developed a
    correction for this.

These problems are also fixed by upstream in Linux 2.4.26 and will be
fixed in Linux 2.6.6."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-481"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel packages immediately, either with a Debian provided
kernel or with a self compiled one.

For the stable distribution (woody) these problems have been fixed in
version 011226.17 for Linux 2.4.17.

 Vulnerability matrix for CAN-2004-0109"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.17-ia64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.17-ia64", reference:"011226.17")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-itanium", reference:"011226.17")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-itanium-smp", reference:"011226.17")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-mckinley", reference:"011226.17")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-mckinley-smp", reference:"011226.17")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.17-ia64", reference:"011226.17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
