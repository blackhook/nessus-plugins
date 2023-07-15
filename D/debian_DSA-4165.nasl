#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4165. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108817);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-8763", "CVE-2018-8764");
  script_xref(name:"DSA", value:"4165");

  script_name(english:"Debian DSA-4165-1 : ldap-account-manager - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michal Kedzior found two vulnerabilities in LDAP Account Manager, a
web front-end for LDAP directories.

  - CVE-2018-8763
    The found Reflected Cross Site Scripting (XSS)
    vulnerability might allow an attacker to execute
    JavaScript code in the browser of the victim or to
    redirect her to a malicious website if the victim clicks
    on a specially crafted link.

  - CVE-2018-8764
    The application leaks the CSRF token in the URL, which
    can be use by an attacker to perform a Cross-Site
    Request Forgery attack, in which a victim logged in LDAP
    Account Manager might performed unwanted actions in the
    front-end by clicking on a link crafted by the attacker."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8764"
  );
  # https://security-tracker.debian.org/tracker/source-package/ldap-account-manager
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e38a554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ldap-account-manager"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ldap-account-manager"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4165"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ldap-account-manager packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 4.7.1-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 5.5-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldap-account-manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/04");
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
if (deb_check(release:"8.0", prefix:"ldap-account-manager", reference:"4.7.1-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ldap-account-manager-lamdaemon", reference:"4.7.1-1+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"ldap-account-manager", reference:"5.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ldap-account-manager-lamdaemon", reference:"5.5-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
