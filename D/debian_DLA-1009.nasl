#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1009-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101175);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679");

  script_name(english:"Debian DLA-1009-1 : apache2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2017-3167

Emmanuel Dreyfus reported that the use of ap_get_basic_auth_pw() by
third-party modules outside of the authentication phase may lead to
authentication requirements being bypassed.

CVE-2017-3169

Vasileios Panopoulos of AdNovum Informatik AG discovered that mod_ssl
may dereference a NULL pointer when third-party modules call
ap_hook_process_connection() during an HTTP request to an HTTPS port
leading to a denial of service.

CVE-2017-7668

Javier Jimenez reported that the HTTP strict parsing contains a flaw
leading to a buffer overread in ap_find_token(). A remote attacker can
take advantage of this flaw by carefully crafting a sequence of
request headers to cause a segmentation fault, or to force
ap_find_token() to return an incorrect value.

CVE-2017-7679

ChenQin and Hanno Boeck reported that mod_mime can read one byte past
the end of a buffer when sending a malicious Content-Type response
header.

For Debian 7 'Wheezy', these problems have been fixed in version
2.2.22-13+deb7u9.

We recommend that you upgrade your apache2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/apache2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
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
if (deb_check(release:"7.0", prefix:"apache2", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-dbg", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-doc", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-event", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-itk", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-prefork", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-worker", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-prefork-dev", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec-custom", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-threaded-dev", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-utils", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-bin", reference:"2.2.22-13+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-common", reference:"2.2.22-13+deb7u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
