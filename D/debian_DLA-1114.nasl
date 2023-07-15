#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1114-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103472);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064");

  script_name(english:"Debian DLA-1114-1 : ruby1.9.1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the Ruby 1.9 interpretor.

CVE-2017-0898

Buffer underrun vulnerability in Kernel.sprintf

CVE-2017-0899

ANSI escape sequence vulnerability

CVE-2017-0900

DOS vulernerability in the query command

CVE-2017-0901

gem installer allows a malicious gem to overwrite arbitrary files

CVE-2017-10784

Escape sequence injection vulnerability in the Basic authentication of
WEBrick

CVE-2017-14033

Buffer underrun vulnerability in OpenSSL ASN1 decode

CVE-2017-14064

Heap exposure vulnerability in generating JSON

For Debian 7 'Wheezy', these problems have been fixed in version
1.9.3.194-8.1+deb7u6.

We recommend that you upgrade your ruby1.9.1 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby1.9.1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.9.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtcltk-ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ri1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");
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
if (deb_check(release:"7.0", prefix:"libruby1.9.1", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.9.1-dbg", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtcltk-ruby1.9.1", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ri1.9.1", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-dev", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-examples", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-full", reference:"1.9.3.194-8.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.3", reference:"1.9.3.194-8.1+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
