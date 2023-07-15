#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3292. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84299);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-1851");
  script_bugtraq_id(75192);
  script_xref(name:"DSA", value:"3292");

  script_name(english:"Debian DSA-3292-1 : cinder - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bastian Blank from credativ discovered that cinder, a
storage-as-a-service system for the OpenStack cloud computing suite,
contained a bug that would allow an authenticated user to read any
file from the cinder server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=788996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/cinder"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3292"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cinder packages.

For the stable distribution (jessie), this problem has been fixed in
version 2014.1.3-11+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cinder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"cinder-api", reference:"2014.1.3-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cinder-backup", reference:"2014.1.3-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cinder-common", reference:"2014.1.3-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cinder-scheduler", reference:"2014.1.3-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cinder-volume", reference:"2014.1.3-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-cinder", reference:"2014.1.3-11+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
