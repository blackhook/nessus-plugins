#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-952-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100431);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-2074", "CVE-2017-6410", "CVE-2017-8422");
  script_bugtraq_id(59808);

  script_name(english:"Debian DLA-952-1 : kde4libs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in kde4libs, the core
libraries for all KDE 4 applications. The Common Vulnerabilities and
Exposures project identifies the following problems :

CVE-2017-6410

Itzik Kotler, Yonatan Fridburg and Amit Klein of Safebreach Labs
reported that URLs are not sanitized before passing them to
FindProxyForURL, potentially allowing a remote attacker to obtain
sensitive information via a crafted PAC file.

CVE-2017-8422

Sebastian Krahmer from SUSE discovered that the KAuth framework
contains a logic flaw in which the service invoking dbus is not
properly checked. This flaw allows spoofing the identity of the caller
and gaining root privileges from an unprivileged account.

CVE-2013-2074

It was discovered that KIO would show web authentication credentials
in some error cases.

For Debian 7 'Wheezy', these problems have been fixed in version
4:4.8.4-4+deb7u3.

We recommend that you upgrade your kde4libs packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/kde4libs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdoctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkcmutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkde3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdeclarative5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdesu5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdeui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdewebkit5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdnssd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkemoticons4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkfile4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkhtml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkidletime4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkimproxy4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkio5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkjsapi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkjsembed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkmediaplayer4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libknewstuff2-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libknewstuff3-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libknotifyconfig4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkntlm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkparts4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkprintutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpty4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrosscore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrossui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libktexteditor4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkunitconversion4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnepomuk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnepomukquery4a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnepomukutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplasma3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolid4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libthreadweaver4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"kdelibs-bin", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"kdelibs5-data", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"kdelibs5-dbg", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"kdelibs5-dev", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"kdelibs5-plugins", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"kdoctools", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkcmutils4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkde3support4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkdeclarative5", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkdecore5", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkdesu5", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkdeui5", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkdewebkit5", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkdnssd4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkemoticons4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkfile4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkhtml5", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkidletime4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkimproxy4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkio5", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkjsapi4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkjsembed4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkmediaplayer4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libknewstuff2-4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libknewstuff3-4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libknotifyconfig4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkntlm4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkparts4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkprintutils4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkpty4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkrosscore4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkrossui4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libktexteditor4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkunitconversion4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libkutils4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libnepomuk4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libnepomukquery4a", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libnepomukutils4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libplasma3", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsolid4", reference:"4:4.8.4-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libthreadweaver4", reference:"4:4.8.4-4+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
