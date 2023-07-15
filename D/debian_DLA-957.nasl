#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-957-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100477);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138");

  script_name(english:"Debian DLA-957-1 : bind9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-3136

Oleg Gorokhov of Yandex discovered that BIND does not properly handle
certain queries when using DNS64 with the 'break-dnssec yes;' option,
allowing a remote attacker to cause a denial of service.

CVE-2017-3137

It was discovered that BIND makes incorrect assumptions about the
ordering of records in the answer section of a response containing
CNAME or DNAME resource records, leading to situations where BIND
exits with an assertion failure. An attacker can take advantage of
this condition to cause a denial of service.

CVE-2017-3138

Mike Lalumiere of Dyn, Inc. discovered that BIND can exit with a
REQUIRE assertion failure if it receives a null command string on its
control channel. Note that the fix applied in Debian is only applied
as a hardening measure. Details about the issue can be found at
https://kb.isc.org/article/AA-01471 .

For Debian 7 'Wheezy', these problems have been fixed in version
1:9.8.4.dfsg.P1-6+nmu2+deb7u16.

We recommend that you upgrade your bind9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://kb.isc.org/article/AA-01471
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bind9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind9-80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns88");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg82");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwres80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"bind9", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-doc", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"bind9utils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"dnsutils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libbind-dev", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libbind9-80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libdns88", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libisc84", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libisccc80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libisccfg82", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"liblwres80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"lwresd", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
