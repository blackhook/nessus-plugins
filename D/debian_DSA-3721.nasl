#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3721. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95034);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797");
  script_xref(name:"DSA", value:"3721");

  script_name(english:"Debian DSA-3721-1 : tomcat7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine, which may result in possible timing attacks to
determine valid user names, bypass of the SecurityManager, disclosure
of system properties, unrestricted access to global resources,
arbitrary file overwrites, and potentially escalation of privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=841655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/tomcat7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3721"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat7 packages.

For the stable distribution (jessie), these problems have been fixed
in version 7.0.56-3+deb8u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
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
if (deb_check(release:"8.0", prefix:"libservlet3.0-java", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libservlet3.0-java-doc", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libtomcat7-java", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-admin", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-common", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-docs", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-examples", reference:"7.0.56-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-user", reference:"7.0.56-3+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
