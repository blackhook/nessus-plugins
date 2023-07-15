#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1772-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124417);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-10746");

  script_name(english:"Debian DLA-1772-1 : libvirt security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libvirt-domain.c in libvirt supports virDomainGetTime API calls by
guest agents with an RO connection, even though an RW connection was
supposed to be required. This could lead to could lead to potentially
disclosing unintended information or denial of service by causing
libvirt to block.

For Debian 8 'Jessie', this problem has been fixed in version
1.2.9-9+deb8u6.

We recommend that you upgrade your libvirt packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/04/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvirt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt0-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libvirt-bin", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-clients", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon-system", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-dev", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-doc", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-sanlock", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0", reference:"1.2.9-9+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0-dbg", reference:"1.2.9-9+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
