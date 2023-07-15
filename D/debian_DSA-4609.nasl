#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4609. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133230);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/14");

  script_cve_id("CVE-2019-15795", "CVE-2019-15796");
  script_xref(name:"DSA", value:"4609");

  script_name(english:"Debian DSA-4609-1 : python-apt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security issues were found in the Python interface to the apt
package manager; package downloads from unsigned repositories were
incorrectly rejected and the hash validation relied on MD5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=944696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/python-apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/python-apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4609"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-apt packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 1.4.1.

For the stable distribution (buster), these problems have been fixed
in version 1.8.4.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"python-apt", reference:"1.8.4.1")) flag++;
if (deb_check(release:"10.0", prefix:"python-apt-common", reference:"1.8.4.1")) flag++;
if (deb_check(release:"10.0", prefix:"python-apt-dbg", reference:"1.8.4.1")) flag++;
if (deb_check(release:"10.0", prefix:"python-apt-dev", reference:"1.8.4.1")) flag++;
if (deb_check(release:"10.0", prefix:"python-apt-doc", reference:"1.8.4.1")) flag++;
if (deb_check(release:"10.0", prefix:"python3-apt", reference:"1.8.4.1")) flag++;
if (deb_check(release:"10.0", prefix:"python3-apt-dbg", reference:"1.8.4.1")) flag++;
if (deb_check(release:"9.0", prefix:"python-apt", reference:"1.4.1")) flag++;
if (deb_check(release:"9.0", prefix:"python-apt-common", reference:"1.4.1")) flag++;
if (deb_check(release:"9.0", prefix:"python-apt-dbg", reference:"1.4.1")) flag++;
if (deb_check(release:"9.0", prefix:"python-apt-dev", reference:"1.4.1")) flag++;
if (deb_check(release:"9.0", prefix:"python-apt-doc", reference:"1.4.1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-apt", reference:"1.4.1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-apt-dbg", reference:"1.4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
