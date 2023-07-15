#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4191. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109558);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2017-15568", "CVE-2017-15569", "CVE-2017-15570", "CVE-2017-15571", "CVE-2017-15572", "CVE-2017-15573", "CVE-2017-15574", "CVE-2017-15575", "CVE-2017-15576", "CVE-2017-15577", "CVE-2017-16804", "CVE-2017-18026");
  script_xref(name:"DSA", value:"4191");

  script_name(english:"Debian DSA-4191-1 : redmine - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in Redmine, a project
management web application. They could lead to remote code execution,
information disclosure or cross-site scripting attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=887307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/redmine"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/redmine"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4191"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the redmine packages.

For the stable distribution (stretch), these problems have been fixed
in version 3.3.1-4+deb9u1.

In addition, this message serves as an announcement that security
support for redmine in the Debian 8 oldstable release (jessie) is now
discontinued.

Users of redmine in Debian 8 that want security updates are strongly
encouraged to upgrade now to the current Debian 9 stable release
(stretch)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redmine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"redmine", reference:"3.3.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"redmine-mysql", reference:"3.3.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"redmine-pgsql", reference:"3.3.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"redmine-sqlite", reference:"3.3.1-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
