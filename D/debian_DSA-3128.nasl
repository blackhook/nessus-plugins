#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3128. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80558);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-6885", "CVE-2014-8133", "CVE-2014-9419", "CVE-2014-9529", "CVE-2014-9584");
  script_bugtraq_id(63983, 71684, 71794, 71880, 71883);
  script_xref(name:"DSA", value:"3128");

  script_name(english:"Debian DSA-3128-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or information leaks.

  - CVE-2013-6885
    It was discovered that under specific circumstances, a
    combination of write operations to write-combined memory
    and locked CPU instructions may cause a core hang on AMD
    16h 00h through 0Fh processors. A local user can use
    this flaw to mount a denial of service (system hang) via
    a crafted application.

  For more information please refer to the AMD CPU erratum 793 in
  http://support.amd.com/TechDocs/51810_16h_00h-0Fh_Rev_Guide.pdf

  - CVE-2014-8133
    It was found that the espfix funcionality can be
    bypassed by installing a 16-bit RW data segment into GDT
    instead of LDT (which espfix checks for) and using it
    for stack. A local unprivileged user could potentially
    use this flaw to leak kernel stack addresses and thus
    allowing to bypass the ASLR protection mechanism.

  - CVE-2014-9419
    It was found that on Linux kernels compiled with the 32
    bit interfaces (CONFIG_X86_32) a malicious user program
    can do a partial ASLR bypass through TLS base addresses
    leak when attacking other programs.

  - CVE-2014-9529
    It was discovered that the Linux kernel is affected by a
    race condition flaw when doing key garbage collection,
    allowing local users to cause a denial of service
    (memory corruption or panic).

  - CVE-2014-9584
    It was found that the Linux kernel does not validate a
    length value in the Extensions Reference (ER) System Use
    Field, which allows local users to obtain sensitive
    information from kernel memory via a crafted iso9660
    image."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6885"
  );
  # http://support.amd.com/TechDocs/51810_16h_00h-0Fh_Rev_Guide.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5360cb0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3128"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.2.65-1+deb7u1. Additionally this update fixes a
suspend/resume regression introduced with 3.2.65.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), these problems will be fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.65-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
