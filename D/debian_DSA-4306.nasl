#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4306. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117812);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_cve_id("CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-1061", "CVE-2018-14647");
  script_xref(name:"DSA", value:"4306");

  script_name(english:"Debian DSA-4306-1 : python2.7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in Python: ElementTree failed
to initialise Expat's hash salt, two denial of service issues were
found in difflib and poplib and the shutil module was affected by a
command injection vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/python2.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python2.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4306"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the python2.7 packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.7.13-2+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000802");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"idle-python2.7", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-dbg", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-dev", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-minimal", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-stdlib", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-testsuite", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-dbg", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-dev", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-doc", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-examples", reference:"2.7.13-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-minimal", reference:"2.7.13-2+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
