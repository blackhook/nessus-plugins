#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2459-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143170);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/25");

  script_cve_id("CVE-2020-15586", "CVE-2020-16845");

  script_name(english:"Debian DLA-2459-1 : golang-1.7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two issues have been found in golang-1.7, a Go programming language
compiler version 1.7

CVE-2020-15586 Using the 100-continue in HTTP headers received by a
net/http/Server can lead to a data race involving the connection's
buffered writer.

CVE-2020-16845 Certain invalid inputs to ReadUvarint or ReadVarint
could cause those functions to read an unlimited number of bytes from
the ByteReader argument before returning an error.

For Debian 9 stretch, these problems have been fixed in version
1.7.4-2+deb9u2.

We recommend that you upgrade your golang-1.7 packages.

For the detailed security status of golang-1.7 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/golang-1.7

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/golang-1.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/golang-1.7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16845");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/23");
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
if (deb_check(release:"9.0", prefix:"golang-1.7", reference:"1.7.4-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"golang-1.7-doc", reference:"1.7.4-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"golang-1.7-go", reference:"1.7.4-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"golang-1.7-src", reference:"1.7.4-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
