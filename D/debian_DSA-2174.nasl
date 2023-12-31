#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2174. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52462);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1002");
  script_bugtraq_id(46446);
  script_xref(name:"DSA", value:"2174");

  script_name(english:"Debian DSA-2174-1 : avahi - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Avahi, an implementation of the zeroconf
protocol, can be crashed remotely by a single UDP packet, which may
result in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=614785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/avahi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2174"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the avahi packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.6.23-3lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 0.6.27-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"avahi", reference:"0.6.23-3lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"avahi-autoipd", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"avahi-daemon", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"avahi-dbg", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"avahi-discover", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"avahi-dnsconfd", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"avahi-ui-utils", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"avahi-utils", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-client-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-client3", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-common-data", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-common-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-common3", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-compat-libdnssd-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-compat-libdnssd1", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-core-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-core7", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-glib-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-glib1", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-gobject-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-gobject0", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-qt3-1", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-qt3-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-qt4-1", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-qt4-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-ui-dev", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libavahi-ui0", reference:"0.6.27-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"python-avahi", reference:"0.6.27-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
