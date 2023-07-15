#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1412-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110909);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-18190", "CVE-2017-18248");

  script_name(english:"Debian DLA-1412-1 : cups security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities affecting the cups printing server were found
which can lead to arbitrary IPP command execution and denial of
service.

CVE-2017-18190

A localhost.localdomain whitelist entry in valid_host() in
scheduler/client.c in CUPS before 2.2.2 allows remote attackers to
execute arbitrary IPP commands by sending POST requests to the CUPS
daemon in conjunction with DNS rebinding. The localhost.localdomain
name is often resolved via a DNS server (neither the OS nor the web
browser is responsible for ensuring that localhost.localdomain is
127.0.0.1).

CVE-2017-18248

The add_job function in scheduler/ipp.c in CUPS before 2.2.6, when
D-Bus support is enabled, can be crashed by remote attackers by
sending print jobs with an invalid username, related to a D-Bus
notification.

For Debian 8 'Jessie', these problems have been fixed in version
1.7.5-11+deb8u3.

We recommend that you upgrade your cups packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/cups"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-core-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/05");
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
if (deb_check(release:"8.0", prefix:"cups", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-bsd", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-client", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-common", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-core-drivers", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-daemon", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-dbg", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-ppdc", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"cups-server-common", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcups2", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcups2-dev", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupscgi1", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupscgi1-dev", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsimage2", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsimage2-dev", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsmime1", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsmime1-dev", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsppdc1", reference:"1.7.5-11+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsppdc1-dev", reference:"1.7.5-11+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
