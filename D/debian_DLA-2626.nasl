#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2626-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148623);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/23");

  script_cve_id("CVE-2021-1405");

  script_name(english:"Debian DLA-2626-1 : clamav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the email parsing module in Clam AntiVirus (ClamAV)
Software version 0.103.1 and all prior versions could allow an
unauthenticated, remote attacker to cause a denial of service
condition on an affected device. The vulnerability is due to improper
variable initialization that may result in an NULL pointer read. An
attacker could exploit this vulnerability by sending a crafted email
to an affected device. An exploit could allow the attacker to cause
the ClamAV scanning process crash, resulting in a denial of service
condition.

For Debian 9 stretch, this problem has been fixed in version
0.102.4+dfsg-0+deb9u2.

We recommend that you upgrade your clamav packages.

For the detailed security status of clamav please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/clamav

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/clamav"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/clamav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1405");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"clamav", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-base", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-daemon", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-docs", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-freshclam", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-milter", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-testfiles", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"clamdscan", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libclamav-dev", reference:"0.102.4+dfsg-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libclamav7", reference:"0.102.4+dfsg-0+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
