#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-314-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86127);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_bugtraq_id(75436, 75557);

  script_name(english:"Debian DLA-314-1 : cups security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Petr Sklenar of Red Hat discovered that the texttopdf tool, part of
cups filters, was susceptible to multiple heap-based buffer and
integer overflows due to improper handling of print jobs. This could
allow remote attackers to crash texttopdf or possibly execute
arbitrary code.

For Debian 6 'Squeeze', this issue has been fixed in cups version
1.4.4-7+squeeze10. For Wheezy and Jessie, this has been fixed in the
cups-filter package. We recommend you to upgrade your cups packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsdriver1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsdriver1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"cups", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"cups-bsd", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"cups-client", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"cups-common", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"cups-dbg", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"cups-ppdc", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"cupsddk", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2-dev", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1-dev", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1-dev", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2-dev", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1-dev", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1", reference:"1.4.4-7+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1-dev", reference:"1.4.4-7+squeeze10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
