#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1261-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106411);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380");

  script_name(english:"Debian DLA-1261-1 : clamav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in clamav, the ClamAV
AntiVirus toolkit for Unix. Effects range from denial of service to
potential arbitrary code execution. Additionally, this version fixes a
longstanding issue that has recently resurfaced whereby a malformed
virus signature database can cause an application crash and denial of
service.

CVE-2017-12374

ClamAV has a use-after-free condition arising from a lack of input
validation. A remote attacker could exploit this vulnerability with a
crafted email message to cause a denial of service.

CVE-2017-12375

ClamAV has a buffer overflow vulnerability arising from a lack of
input validation. An unauthenticated remote attacker could send a
crafted email message to the affected device, triggering a buffer
overflow and potentially a denial of service when the malicious
message is scanned.

CVE-2017-12376

ClamAV has a buffer overflow vulnerability arising from improper input
validation when handling Portable Document Format (PDF) files. An
unauthenticated remote attacker could send a crafted PDF file to the
affected device, triggering a buffer overflow and potentially a denial
of service or arbitrary code execution when the malicious file is
scanned.

CVE-2017-12377

ClamAV has a heap overflow vulnerability arising from improper input
validation when handling mew packets. An attacker could exploit this
by sending a crafted message to the affected device, triggering a
denial of service or possible arbitrary code execution when the
malicious file is scanned.

CVE-2017-12378

ClamAV has a buffer overread vulnerability arising from improper input
validation when handling tape archive (TAR) files. An unauthenticated
remote attacker could send a crafted TAR file to the affected device,
triggering a buffer overread and potentially a denial of service when
the malicious file is scanned.

CVE-2017-12379

ClamAV has a buffer overflow vulnerability arising from improper input
validation in the message parsing function. An unauthenticated remote
attacker could send a crafted email message to the affected device,
triggering a buffer overflow and potentially a denial of service or
arbitrary code execution when the malicious message is scanned.

CVE-2017-12380

ClamAV has a NULL dereference vulnerability arising from improper
input validation in the message parsing function. An unauthenticated
remote attacker could send a crafted email message to the affected
device, triggering a NULL pointer dereference, which may result in a
denial of service.

Debian Bug #824196

A malformed virus signature database could cause an application crash
and denial of service.

For Debian 7 'Wheezy', these problems have been fixed in version
0.99.2+dfsg-0+deb7u4.

We recommend that you upgrade your clamav packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/clamav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");
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
if (deb_check(release:"7.0", prefix:"clamav", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-base", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-daemon", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-dbg", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-docs", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-freshclam", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-milter", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-testfiles", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libclamav-dev", reference:"0.99.2+dfsg-0+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libclamav7", reference:"0.99.2+dfsg-0+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
