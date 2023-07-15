#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4161. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108773);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-7536", "CVE-2018-7537");
  script_xref(name:"DSA", value:"4161");

  script_name(english:"Debian DSA-4161-1 : python-django - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"James Davis discovered two issues in Django, a high-level Python web
development framework, that can lead to a denial-of-service attack. An
attacker with control on the input of the django.utils.html.urlize()
function or django.utils.text.Truncator's chars() and words() methods
could craft a string that might stuck the execution of the
application."
  );
  # https://security-tracker.debian.org/tracker/source-package/python-django
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22eb32f6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4161"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-django packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.7.11-1+deb8u3.

For the stable distribution (stretch), these problems have been fixed
in version 1:1.10.7-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");
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
if (deb_check(release:"8.0", prefix:"python-django", reference:"1.7.11-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python-django-common", reference:"1.7.11-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python-django-doc", reference:"1.7.11-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python3-django", reference:"1.7.11-1+deb8u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-django", reference:"1:1.10.7-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-django-common", reference:"1:1.10.7-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-django-doc", reference:"1:1.10.7-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-django", reference:"1:1.10.7-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
