#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3932. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102372);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-8734", "CVE-2017-9800");
  script_xref(name:"DSA", value:"3932");

  script_name(english:"Debian DSA-3932-1 : subversion - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems were discovered in Subversion, a centralised version
control system.

  - CVE-2016-8734
    (jessie only)

  Subversion's mod_dontdothat server module and Subversion clients
  using http(s):// were vulnerable to a denial-of-service attack
  caused by exponential XML entity expansion.

  - CVE-2017-9800
    Joern Schneeweisz discovered that Subversion did not
    correctly handle maliciously constructed svn+ssh://
    URLs. This allowed an attacker to run an arbitrary shell
    command, for instance via svn:externals properties or
    when using 'svnsync sync'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3932"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.8.10-6+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 1.9.5-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/11");
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
if (deb_check(release:"8.0", prefix:"libapache2-mod-svn", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-svn", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-dev", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-doc", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-java", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-perl", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-ruby1.8", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn1", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"python-subversion", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-svn", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"subversion", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"subversion-dbg", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"subversion-tools", reference:"1.8.10-6+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-svn", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-dev", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-doc", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-java", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-perl", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn1", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-subversion", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ruby-svn", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"subversion", reference:"1.9.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"subversion-tools", reference:"1.9.5-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
