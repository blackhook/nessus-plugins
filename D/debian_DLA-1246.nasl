#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1246-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106173);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-5702");

  script_name(english:"Debian DLA-1246-1 : transmission security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered a vulnerability in the Transmission
BitTorrent client; insecure RPC handling between the Transmission
daemon and the client interface(s) may result in the execution of
arbitrary code if a user visits a malicious website while Transmission
is running.

For Debian 7 'Wheezy', these problems have been fixed in version
2.52-3+nmu3.

We recommend that you upgrade your transmission packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/transmission"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"transmission", reference:"2.52-3+nmu3")) flag++;
if (deb_check(release:"7.0", prefix:"transmission-cli", reference:"2.52-3+nmu3")) flag++;
if (deb_check(release:"7.0", prefix:"transmission-common", reference:"2.52-3+nmu3")) flag++;
if (deb_check(release:"7.0", prefix:"transmission-daemon", reference:"2.52-3+nmu3")) flag++;
if (deb_check(release:"7.0", prefix:"transmission-dbg", reference:"2.52-3+nmu3")) flag++;
if (deb_check(release:"7.0", prefix:"transmission-gtk", reference:"2.52-3+nmu3")) flag++;
if (deb_check(release:"7.0", prefix:"transmission-qt", reference:"2.52-3+nmu3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
