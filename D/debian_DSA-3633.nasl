#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3633. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92614);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-8338", "CVE-2016-4480", "CVE-2016-4962", "CVE-2016-5242", "CVE-2016-6258");
  script_xref(name:"DSA", value:"3633");
  script_xref(name:"IAVB", value:"2016-B-0118-S");

  script_name(english:"Debian DSA-3633-1 : xen - security update (Bunker Buster)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2015-8338
    Julien Grall discovered that Xen on ARM was susceptible
    to denial of service via long running memory operations.

  - CVE-2016-4480
    Jan Beulich discovered that incorrect page table
    handling could result in privilege escalation inside a
    Xen guest instance.

  - CVE-2016-4962
    Wei Liu discovered multiple cases of missing input
    sanitising in libxl which could result in denial of
    service.

  - CVE-2016-5242
    Aaron Cornelius discovered that incorrect resource
    handling on ARM systems could result in denial of
    service.

  - CVE-2016-6258
    Jeremie Boutoille discovered that incorrect pagetable
    handling in PV instances could result in guest to host
    privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3633"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (jessie), these problems have been fixed
in version 4.4.1-9+deb8u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libxen-4.4", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libxen-dev", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libxenstore3.0", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-amd64", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-arm64", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-armhf", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-amd64", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-arm64", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-armhf", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-4.4", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-common", reference:"4.4.1-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xenstore-utils", reference:"4.4.1-9+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
