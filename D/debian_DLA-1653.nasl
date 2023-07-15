#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1653-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121518);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-18359");

  script_name(english:"Debian DLA-1653-1 : postgis security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the function ST_AsX3D in PostGIS, a module that adds
spatial objects to the PostgreSQL object-relational database, did not
handle empty values properly, allowing malicious users to cause denial
of service or possibly other unspecified behaviour.

For Debian 8 'Jessie', this problem has been fixed in version
2.1.4+dfsg-3+deb8u1.

We recommend that you upgrade your postgis packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/postgis"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwgeom-2.1.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwgeom-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostgis-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostgis-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgis-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.4-postgis-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.4-postgis-2.1-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.4-postgis-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"liblwgeom-2.1.4", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"liblwgeom-dev", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpostgis-java", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpostgis-java-doc", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgis", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgis-doc", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4-postgis-2.1", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4-postgis-2.1-scripts", reference:"2.1.4+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4-postgis-scripts", reference:"2.1.4+dfsg-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
