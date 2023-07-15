#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-992-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100875);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000366");

  script_name(english:"Debian DLA-992-1 : eglibc security update (Stack Clash)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Qualys Research Labs discovered various problems in the dynamic
linker of the GNU C Library which allow local privilege escalation by
clashing the stack. For the full details, please refer to their
advisory published at:
https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt

For Debian 7 'Wheezy', these problems have been fixed in version
2.13-38+deb7u12.

We recommend that you upgrade your eglibc packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/eglibc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eglibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc0.1-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-mips64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-mipsn32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-sparc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-loongson2f");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-mips64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-mipsn32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-sparc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6.1-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6.1-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"7.0", prefix:"eglibc-source", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"glibc-doc", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc-bin", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc-dev-bin", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dbg", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev-i386", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i386", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i686", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-pic", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-prof", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-amd64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dbg", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-amd64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-i386", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mips64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mipsn32", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-ppc64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390x", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-sparc64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i386", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i686", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-loongson2f", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mips64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mipsn32", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-pic", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-ppc64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-prof", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390x", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-sparc64", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-xen", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dbg", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dev", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-pic", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-prof", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"locales", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"locales-all", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"multiarch-support", reference:"2.13-38+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"nscd", reference:"2.13-38+deb7u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
