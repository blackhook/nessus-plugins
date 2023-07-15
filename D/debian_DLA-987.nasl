#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-987-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100817);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-6127", "CVE-2017-5361", "CVE-2017-5943", "CVE-2017-5944");

  script_name(english:"Debian DLA-987-1 : request-tracker4 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Request Tracker, an
extensible trouble-ticket tracking system. The Common Vulnerabilities
and Exposures project identifies the following problems :

CVE-2016-6127

It was discovered that Request Tracker is vulnerable to a cross-site
scripting (XSS) attack if an attacker uploads a malicious file with a
certain content type. Installations which use the
AlwaysDownloadAttachments config setting are unaffected by this flaw.
The applied fix addresses all existant and future uploaded
attachments.

CVE-2017-5361

It was discovered that Request Tracker is vulnerable to timing
side-channel attacks for user passwords.

CVE-2017-5943

It was discovered that Request Tracker is prone to an information leak
of cross-site request forgery (CSRF) verification tokens if a user is
tricked into visiting a specially crafted URL by an attacker.

CVE-2017-5944

It was discovered that Request Tracker is prone to a remote code
execution vulnerability in the dashboard subscription interface. A
privileged attacker can take advantage of this flaw through
carefully-crafted saved search names to cause unexpected code to be
executed. The applied fix addresses all existant and future saved
searches.

Additionally to the above mentioned CVEs, this update works around
CVE-2015-7686 in Email::Address which could induce a denial of service
of Request Tracker itself.

For Debian 7 'Wheezy', these problems have been fixed in version
4.0.7-5+deb7u5.

We recommend that you upgrade your request-tracker4 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/request-tracker4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-fcgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");
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
if (deb_check(release:"7.0", prefix:"request-tracker4", reference:"4.0.7-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-apache2", reference:"4.0.7-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-clients", reference:"4.0.7-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-mysql", reference:"4.0.7-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-postgresql", reference:"4.0.7-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-sqlite", reference:"4.0.7-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-fcgi", reference:"4.0.7-5+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
