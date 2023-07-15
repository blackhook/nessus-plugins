#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1503-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117464);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-16657");

  script_name(english:"Debian DLA-1503-1 : kamailio security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a denial of service and a potential
arbitrary code execution vulnerability in the kamailio SIP server.

A specially crafted SIP message with an invalid 'Via' header could
cause a segmentation fault and crash Kamailio due to missing input
validation.

For Debian 8 'Jessie', this issue has been fixed in kamailio version
4.2.0-2+deb8u5.

We recommend that you upgrade your kamailio packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/kamailio"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-autheph-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-berkeley-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-berkeley-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-carrierroute-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-cpl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-dnssec-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-extra-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-geoip-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-ims-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-java-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-json-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-ldap-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-lua-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-memcached-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-mono-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-mysql-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-outbound-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-perl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-postgres-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-presence-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-python-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-radius-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-redis-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-sctp-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-snmpstats-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-sqlite-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-tls-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-unixodbc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-utils-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-websocket-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-xml-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-xmpp-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");
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
if (deb_check(release:"8.0", prefix:"kamailio", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-autheph-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-berkeley-bin", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-berkeley-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-carrierroute-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-cpl-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-dbg", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-dnssec-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-extra-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-geoip-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-ims-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-java-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-json-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-ldap-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-lua-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-memcached-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-mono-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-mysql-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-outbound-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-perl-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-postgres-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-presence-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-python-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-radius-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-redis-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-sctp-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-snmpstats-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-sqlite-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-tls-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-unixodbc-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-utils-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-websocket-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-xml-modules", reference:"4.2.0-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-xmpp-modules", reference:"4.2.0-2+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
