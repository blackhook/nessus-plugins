#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2423-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142153);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903", "CVE-2019-12295");

  script_name(english:"Debian DLA-2423-1 : wireshark security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were fixed in the Wireshark network protocol
analyzer.

CVE-2019-10894

GSS-API dissector crash

CVE-2019-10895

NetScaler file parser crash

CVE-2019-10896

DOF dissector crash

CVE-2019-10899

SRVLOC dissector crash

CVE-2019-10901

LDSS dissector crash

CVE-2019-10903

DCERPC SPOOLSS dissector crash

CVE-2019-12295

Dissection engine could crash

For Debian 9 stretch, these problems have been fixed in version
2.6.8-1.1~deb9u1.

We recommend that you upgrade your wireshark packages.

For the detailed security status of wireshark please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/wireshark

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wireshark"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");
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
if (deb_check(release:"9.0", prefix:"libwireshark-data", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwireshark-dev", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwireshark8", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwiretap-dev", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwiretap6", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwscodecs1", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwsutil-dev", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwsutil7", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tshark", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-common", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-dev", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-doc", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-gtk", reference:"2.6.8-1.1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-qt", reference:"2.6.8-1.1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
