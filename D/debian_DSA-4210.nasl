#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4210. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110102);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");
  script_xref(name:"DSA", value:"4210");

  script_name(english:"Debian DSA-4210-1 : xen - security update (Spectre)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update provides mitigations for the Spectre v4 variant in
x86-based micro processors. On Intel CPUs this requires updated
microcode which is currently not released publicly (but your hardware
vendor may have issued an update). For servers with AMD CPUs no
microcode update is needed, please refer to
https://xenbits.xen.org/xsa/advisory-263.html for further information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://xenbits.xen.org/xsa/advisory-263.html"
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
    value:"https://www.debian.org/security/2018/dsa-4210"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the xen packages.

For the stable distribution (stretch), this problem has been fixed in
version 4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
