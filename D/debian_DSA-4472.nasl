#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4472. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126351);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-20843");
  script_xref(name:"DSA", value:"4472");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DSA-4472-1 : expat - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that Expat, an XML parsing C library, did not
properly handled XML input including XML names that contain a large
number of colons, potentially resulting in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=931031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/expat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/expat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4472"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the expat packages.

For the stable distribution (stretch), this problem has been fixed in
version 2.2.0-2+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:expat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"expat", reference:"2.2.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"lib64expat1", reference:"2.2.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"lib64expat1-dev", reference:"2.2.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libexpat1", reference:"2.2.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libexpat1-dev", reference:"2.2.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libexpat1-udeb", reference:"2.2.0-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
