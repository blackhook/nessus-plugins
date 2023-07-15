#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4046. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104752);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-8028");
  script_xref(name:"DSA", value:"4046");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DSA-4046-1 : libspring-ldap-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Tobias Schneider discovered that libspring-ldap-java, a Java library
for Spring-based applications using the Lightweight Directory Access
Protocol, would under some circumstances allow authentication with a
correct username but an arbitrary password.");
  # https://security-tracker.debian.org/tracker/source-package/libspring-ldap-java
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59d1917c");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/libspring-ldap-java");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2017/dsa-4046");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libspring-ldap-java packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.3.1.RELEASE-5+deb8u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-ldap-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"libspring-ldap-java", reference:"1.3.1.RELEASE-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-ldap-java-doc", reference:"1.3.1.RELEASE-5+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
