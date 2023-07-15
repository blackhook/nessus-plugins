#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4050. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104819);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14316", "CVE-2017-14317", "CVE-2017-14318", "CVE-2017-14319", "CVE-2017-15588", "CVE-2017-15589", "CVE-2017-15590", "CVE-2017-15592", "CVE-2017-15593", "CVE-2017-15594", "CVE-2017-15595", "CVE-2017-15597", "CVE-2017-17044", "CVE-2017-17045", "CVE-2017-17046");
  script_xref(name:"DSA", value:"4050");

  script_name(english:"Debian DSA-4050-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor,
which could result in denial of service, information leaks, privilege
escalation or the execution of arbitrary code."
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
    value:"https://www.debian.org/security/2017/dsa-4050"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the oldstable distribution (jessie) a separate update will be
released.

For the stable distribution (stretch), these problems have been fixed
in version 4.8.2+xsa245-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/29");
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
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.2+xsa245-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.2+xsa245-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
