#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4623. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133700);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/31");

  script_cve_id("CVE-2020-1720");
  script_xref(name:"DSA", value:"4623");

  script_name(english:"Debian DSA-4623-1 : postgresql-11 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tom Lane discovered that 'ALTER ... DEPENDS ON EXTENSION' sub commands
in the PostgreSQL database did not perform authorisation checks."
  );
  # https://security-tracker.debian.org/tracker/source-package/postgresql-11
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e0872ee"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/postgresql-11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4623"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-11 packages.

For the stable distribution (buster), this problem has been fixed in
version 11.7-0+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1720");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libecpg-compat3", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libecpg-dev", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libecpg6", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpgtypes3", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpq-dev", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpq5", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-11", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-client-11", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-doc-11", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-plperl-11", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-plpython-11", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-plpython3-11", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-pltcl-11", reference:"11.7-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"postgresql-server-dev-11", reference:"11.7-0+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
