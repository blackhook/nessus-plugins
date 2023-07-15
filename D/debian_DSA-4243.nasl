#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4243. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111014);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2017-15400", "CVE-2018-4180", "CVE-2018-4181", "CVE-2018-6553");
  script_xref(name:"DSA", value:"4243");

  script_name(english:"Debian DSA-4243-1 : cups - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in CUPS, the Common UNIX
Printing System. These issues have been identified with the following
CVE ids :

  - CVE-2017-15400
    Rory McNamara discovered that an attacker is able to
    execute arbitrary commands (with the privilege of the
    CUPS daemon) by setting a malicious IPP server with a
    crafted PPD file.

  - CVE-2018-4180
    Dan Bastone of Gotham Digital Science discovered that a
    local attacker with access to cupsctl could escalate
    privileges by setting an environment variable. 

  - CVE-2018-4181
    Eric Rafaloff and John Dunlap of Gotham Digital Science
    discovered that a local attacker can perform limited
    reads of arbitrary files as root by manipulating
    cupsd.conf.

  - CVE-2018-6553
    Dan Bastone of Gotham Digital Science discovered that an
    attacker can bypass the AppArmor cupsd sandbox by
    invoking the dnssd backend using an alternate name that
    has been hard linked to dnssd."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-4180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-4181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4243"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.2.1-8+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");
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
if (deb_check(release:"9.0", prefix:"cups", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-bsd", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-client", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-common", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-core-drivers", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-daemon", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-ipp-utils", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-ppdc", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cups-server-common", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcups2", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcups2-dev", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcupscgi1", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcupsimage2", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcupsimage2-dev", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcupsmime1", reference:"2.2.1-8+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcupsppdc1", reference:"2.2.1-8+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
