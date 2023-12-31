#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-439. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15276);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2003-0961", "CVE-2003-0985", "CVE-2004-0077");
  script_bugtraq_id(9686);
  script_xref(name:"CERT", value:"981222");
  script_xref(name:"DSA", value:"439");

  script_name(english:"Debian DSA-439-1 : linux-kernel-2.4.16-arm - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local root exploits have been discovered recently in the Linux
kernel. This security advisory updates the ARM kernel for Debian
GNU/Linux. The Common Vulnerabilities and Exposures project identifies
the following problems that are fixed with this update :

  - CAN-2003-0961 :
    An integer overflow in brk() system call (do_brk()
    function) for Linux allows a local attacker to gain root
    privileges. Fixed upstream in Linux 2.4.23.

  - CAN-2003-0985 :

    Paul Starzetz discovered a flaw in bounds checking in
    mremap() in the Linux kernel (present in version 2.4.x
    and 2.6.x) which may allow a local attacker to gain root
    privileges. Version 2.2 is not affected by this bug.
    Fixed upstream in Linux 2.4.24.

  - CAN-2004-0077 :

    Paul Starzetz and Wojciech Purczynski of isec.pl
    discovered a critical security vulnerability in the
    memory management code of Linux inside the mremap(2)
    system call. Due to missing function return value check
    of internal functions a local attacker can gain root
    privileges. Fixed upstream in Linux 2.4.25 and 2.6.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0013-mremap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-439"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Linux kernel packages immediately.

For the stable distribution (woody) these problems have been fixed in
version 2.4.16-20040204 of lart, netwinder and riscpc image and in
version 20040204 of kernel-patch-2.4.16-arm.

Other architectures will probably be mentioned in a separate advisory
or are not affected (m68k).

 Vulnerability matrix for CAN-2004-0077"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.16-lart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.16-netwinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.16-riscpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-patch-2.4.16-arm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.16", reference:"20040204")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.16-lart", reference:"20040204")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.16-netwinder", reference:"20040204")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.16-riscpc", reference:"20040204")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-patch-2.4.16-arm", reference:"20040204")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
