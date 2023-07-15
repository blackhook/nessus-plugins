#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2355-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140054);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-8622", "CVE-2020-8623");
  script_xref(name:"IAVA", value:"2020-A-0385-S");

  script_name(english:"Debian DLA-2355-1 : bind9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two issues have been found in bind9, an Internet Domain Name Server.

CVE-2020-8622

Crafted responses to TSIG-signed requests could lead to an assertion
failure, causing the server to exit. This could be done by malicious
server operators or guessing attackers.

CVE-2020-8623

An assertions failure, causing the server to exit, can be exploited by
a query for an RSA signed zone.

For Debian 9 stretch, these problems have been fixed in version
1:9.10.3.dfsg.P4-12.3+deb9u7.

We recommend that you upgrade your bind9 packages.

For the detailed security status of bind9 please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/bind9

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00053.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/bind9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/bind9");
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-export-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind9-140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns-export162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns-export162-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libirs-export141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libirs-export141-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libirs141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc-export160-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc-export140-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg-export140-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwres141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"bind9", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"bind9-doc", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"bind9-host", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"bind9utils", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dnsutils", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"host", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libbind-dev", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libbind-export-dev", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libbind9-140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libdns-export162", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libdns-export162-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libdns162", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libirs-export141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libirs-export141-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libirs141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisc-export160", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisc-export160-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisc160", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc-export140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc-export140-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg-export140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg-export140-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"liblwres141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"lwresd", reference:"1:9.10.3.dfsg.P4-12.3+deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
