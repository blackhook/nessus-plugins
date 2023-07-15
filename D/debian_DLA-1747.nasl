#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1747-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123567);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-5383");

  script_name(english:"Debian DLA-1747-1 : firmware-nonfree security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Eli Biham and Lior Neumann discovered a cryptographic weakness in the
Bluetooth LE SC pairing protocol, called the Fixed Coordinate Invalid
Curve Attack (CVE-2018-5383). Depending on the devices used, this
could be exploited by a nearby attacker to obtain sensitive
information, for denial of service, or for other security impact.

This flaw has been fixed in firmware for Intel Wireless 7260 (B3),
7260 (B5), 7265 (D1), and 8264 adapters, and for Qualcomm Atheros
QCA61x4 'ROME' version 3.2 adapters. Other Bluetooth adapters are also
affected and remain vulnerable.

For Debian 8 'Jessie', this problem has been fixed in version
20161130-5~deb8u1.

We recommend that you upgrade your firmware-nonfree packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/04/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/firmware-nonfree"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-adi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-amd-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-atheros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-bnx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-bnx2x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-brcm80211");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-cavium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-intel-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-intelwimax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ipw2x00");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ivtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-iwlwifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-libertas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux-nonfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-misc-nonfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-myricom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-netxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-qlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ralink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-realtek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-samsung");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-siano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ti-connectivity");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/02");
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
if (deb_check(release:"8.0", prefix:"firmware-adi", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-amd-graphics", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-atheros", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-bnx2", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-bnx2x", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-brcm80211", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-cavium", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-intel-sound", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-intelwimax", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-ipw2x00", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-ivtv", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-iwlwifi", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-libertas", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-linux", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-linux-nonfree", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-misc-nonfree", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-myricom", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-netxen", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-qlogic", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-ralink", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-realtek", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-samsung", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-siano", reference:"20161130-5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firmware-ti-connectivity", reference:"20161130-5~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
