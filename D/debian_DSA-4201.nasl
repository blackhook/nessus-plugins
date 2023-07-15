#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4201. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109816);
  script_version("1.13");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-10471", "CVE-2018-10472", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-8897");
  script_xref(name:"DSA", value:"4201");

  script_name(english:"Debian DSA-4201-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor :

  - CVE-2018-8897
    Andy Lutomirski and Nick Peterson discovered that
    incorrect handling of debug exceptions could result in
    privilege escalation.

  - CVE-2018-10471
    An error was discovered in the mitigations against
    Meltdown which could result in denial of service.

  - CVE-2018-10472
    Anthony Perard discovered that incorrect parsing of
    CDROM images can result in information disclosure.

  - CVE-2018-10981
    Jan Beulich discovered that malformed device models
    could result in denial of service.

  - CVE-2018-10982
    Roger Pau Monne discovered that incorrect handling of
    high precision event timers could result in denial of
    service and potentially privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10982"
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
    value:"https://www.debian.org/security/2018/dsa-4201"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
