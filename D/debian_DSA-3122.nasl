#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3122. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80421);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-8150");
  script_xref(name:"DSA", value:"3122");

  script_name(english:"Debian DSA-3122-1 : curl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrey Labunets of Facebook discovered that cURL, an URL transfer
library, fails to properly handle URLs with embedded end-of-line
characters. An attacker able to make an application using libcurl to
access a specially crafted URL via an HTTP proxy could use this flaw
to do additional requests in a way that was not intended, or insert
additional request headers into the request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3122"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the stable distribution (wheezy), this problem has been fixed in
version 7.26.0-1+wheezy12.

For the upcoming stable distribution (jessie), this problem will be
fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"curl", reference:"7.26.0-1+wheezy12")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3", reference:"7.26.0-1+wheezy12")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-dbg", reference:"7.26.0-1+wheezy12")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-gnutls", reference:"7.26.0-1+wheezy12")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-nss", reference:"7.26.0-1+wheezy12")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-gnutls-dev", reference:"7.26.0-1+wheezy12")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-nss-dev", reference:"7.26.0-1+wheezy12")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-openssl-dev", reference:"7.26.0-1+wheezy12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
