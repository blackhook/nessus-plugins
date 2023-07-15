#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1132-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103791);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915", "CVE-2017-10918", "CVE-2017-10920", "CVE-2017-10921", "CVE-2017-10922", "CVE-2017-12135", "CVE-2017-12137", "CVE-2017-12855", "CVE-2017-14316", "CVE-2017-14317", "CVE-2017-14318", "CVE-2017-14319");
  script_xref(name:"IAVB", value:"2017-B-0074-S");

  script_name(english:"Debian DLA-1132-1 : xen security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor :

CVE-2017-10912

Jann Horn discovered that incorrectly handling of page transfers might
result in privilege escalation.

CVE-2017-10913 / CVE-2017-10914

Jann Horn discovered that race conditions in grant handling might
result in information leaks or privilege escalation.

CVE-2017-10915

Andrew Cooper discovered that incorrect reference counting with shadow
paging might result in privilege escalation.

CVE-2017-10918

Julien Grall discovered that incorrect error handling in
physical-to-machine memory mappings may result in privilege
escalation, denial of service or an information leak.

CVE-2017-10920 / CVE-2017-10921 / CVE-2017-10922

Jan Beulich discovered multiple places where reference counting on
grant table operations was incorrect, resulting in potential privilege
escalation

CVE-2017-12135

Jan Beulich found multiple problems in the handling of transitive
grants which could result in denial of service and potentially
privilege escalation.

CVE-2017-12137

Andrew Cooper discovered that incorrect validation of grants may
result in privilege escalation.

CVE-2017-12855

Jan Beulich discovered that incorrect grant status handling, thus
incorrectly informing the guest that the grant is no longer in use.

CVE-2017-14316

Matthew Daley discovered that the NUMA node parameter wasn't verified
which which may result in privilege escalation.

CVE-2017-14317

Eric Chanudet discovered that a race conditions in cxenstored might
result in information leaks or privilege escalation.

CVE-2017-14318

Matthew Daley discovered that incorrect validation of grants may
result in a denial of service.

CVE-2017-14319

Andrew Cooper discovered that insufficient grant unmapping checks may
result in denial of service and privilege escalation.

For Debian 7 'Wheezy', these problems have been fixed in version
4.1.6.lts1-9.

We recommend that you upgrade your xen packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/10/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenstore3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-docs-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.1-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.1-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xenstore-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.6.lts1-9")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.6.lts1-9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
