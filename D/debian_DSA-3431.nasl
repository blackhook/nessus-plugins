#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3431. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87739);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-7944", "CVE-2015-7945");
  script_xref(name:"DSA", value:"3431");

  script_name(english:"Debian DSA-3431-1 : ganeti - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Pierre Kim discovered two vulnerabilities in the restful API of
Ganeti, a virtual server cluster management tool. SSL parameter
negotiation could result in denial of service and the DRBD secret
could leak."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ganeti"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ganeti"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3431"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ganeti packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 2.5.2-1+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 2.12.4-1+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ganeti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"ganeti-htools", reference:"2.5.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ganeti2", reference:"2.5.2-1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"ganeti", reference:"2.12.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ganeti-2.12", reference:"2.12.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ganeti-doc", reference:"2.12.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ganeti-haskell-2.12", reference:"2.12.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ganeti-htools", reference:"2.12.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ganeti-htools-2.12", reference:"2.12.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ganeti2", reference:"2.12.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-ganeti-rapi", reference:"2.12.4-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
