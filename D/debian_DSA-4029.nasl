#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4029. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104485);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-8806");
  script_xref(name:"DSA", value:"4029");

  script_name(english:"Debian DSA-4029-1 : postgresql-common - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the pg_ctlcluster, pg_createcluster and
pg_upgradecluster commands handled symbolic links insecurely which
could result in local denial of service by overwriting arbitrary
files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/postgresql-common"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/postgresql-common"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4029"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-common packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 9.4+165+deb8u3.

For the stable distribution (stretch), this problem has been fixed in
version 9.6+181+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/10");
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
if (deb_check(release:"8.0", prefix:"postgresql", reference:"9.4+165+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-client", reference:"9.4+165+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-contrib", reference:"9.4+165+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-doc", reference:"9.4+165+deb8u3")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql", reference:"9.6+181+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-all", reference:"9.6+181+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-client", reference:"9.6+181+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-contrib", reference:"9.6+181+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-doc", reference:"9.6+181+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
