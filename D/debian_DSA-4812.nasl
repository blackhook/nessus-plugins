#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4812. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144322);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-29479", "CVE-2020-29480", "CVE-2020-29481", "CVE-2020-29482", "CVE-2020-29483", "CVE-2020-29484", "CVE-2020-29485", "CVE-2020-29486", "CVE-2020-29566", "CVE-2020-29570", "CVE-2020-29571");
  script_xref(name:"DSA", value:"4812");
  script_xref(name:"IAVB", value:"2020-B-0077-S");

  script_name(english:"Debian DSA-4812-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor :

Several security issues affecting Xenstore could result in cross
domain access (denial of service, information leaks or privilege
escalation) or denial of service against xenstored.

Additional vulnerabilities could result in guest-to-host denial of
service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4812"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the xen packages.

For the stable distribution (buster), these problems have been fixed
in version 4.11.4+57-g41a822c392-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29479");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (deb_check(release:"10.0", prefix:"libxen-dev", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxencall1", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxendevicemodel1", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxenevtchn1", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxenforeignmemory1", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxengnttab1", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxenmisc4.11", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxenstore3.0", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxentoolcore1", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"libxentoollog1", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-doc", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-4.11-amd64", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-4.11-arm64", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-4.11-armhf", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-common", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-system-amd64", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-system-arm64", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-system-armhf", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-utils-4.11", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xen-utils-common", reference:"4.11.4+57-g41a822c392-2")) flag++;
if (deb_check(release:"10.0", prefix:"xenstore-utils", reference:"4.11.4+57-g41a822c392-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
