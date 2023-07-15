#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4913. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149373);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/01");

  script_cve_id("CVE-2021-3504");
  script_xref(name:"DSA", value:"4913");

  script_name(english:"Debian DSA-4913-1 : hivex - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Jeremy Galindo discovered an out-of-bounds memory access in Hivex, a
library to parse Windows Registry hive files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=988024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/hivex"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/hivex"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4913"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the hivex packages.

For the stable distribution (buster), this problem has been fixed in
version 1.3.18-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3504");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hivex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libhivex-bin", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libhivex-dev", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libhivex-ocaml", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libhivex-ocaml-dev", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libhivex0", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwin-hivex-perl", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python-hivex", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python3-hivex", reference:"1.3.18-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ruby-hivex", reference:"1.3.18-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
