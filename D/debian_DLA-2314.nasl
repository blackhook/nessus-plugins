#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2314-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139387);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/11");

  script_cve_id("CVE-2020-3327", "CVE-2020-3350", "CVE-2020-3481");

  script_name(english:"Debian DLA-2314-1 : clamav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been found in the ClamAV antivirus
toolkit :

CVE-2020-3327

An out of bounds read in the ARJ archive-parsing module could cause
denial of service. The fix in 0.102.3 was incomplete.

CVE-2020-3350

A malicious user could trick clamscan, clamdscan or clamonacc into
moving or removing a different file than intended when those are used
with one of the --move or --remove options. This could be used to get
rid of special system files.

CVE-2020-3481

The EGG archive module was vulnerable to denial of service via NULL pointer dereference due to improper error handling. The official
signature database avoided this problem because the signatures there
avoided the use of the EGG archive parser.

For Debian 9 stretch, these problems have been fixed in version
0.102.4+dfsg-0+deb9u1.

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
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00010.html"
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
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3350");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"clamav", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-base", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-daemon", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-docs", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-freshclam", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-milter", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"clamav-testfiles", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"clamdscan", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libclamav-dev", reference:"0.102.4+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libclamav7", reference:"0.102.4+dfsg-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
