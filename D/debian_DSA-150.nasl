#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-150. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14987);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2002-0874");
  script_bugtraq_id(5453);
  script_xref(name:"DSA", value:"150");

  script_name(english:"Debian DSA-150-1 : interchange - illegal file exposition");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A problem has been discovered in Interchange, an e-commerce and
general HTTP database display system, which can lead to an attacker
being able to read any file to which the user of the Interchange
daemon has sufficient permissions, when Interchange runs in 'INET
mode' (internet domain socket). This is not the default setting in
Debian packages, but configurable with Debconf and via configuration
file. We also believe that this bug cannot exploited on a regular
Debian system.

This problem has been fixed by the package maintainer in version
4.8.3.20020306-1.woody.1 for the current stable distribution (woody)
and in version 4.8.6-1 for the unstable distribution (sid). The old
stable distribution (potato) is not affected, since it doesn't ship
the Interchange system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-150"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the interchange packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:interchange");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"interchange", reference:"4.8.3.20020306-1.woody.1")) flag++;
if (deb_check(release:"3.0", prefix:"interchange-cat-foundation", reference:"4.8.3.20020306-1.woody.1")) flag++;
if (deb_check(release:"3.0", prefix:"interchange-ui", reference:"4.8.3.20020306-1.woody.1")) flag++;
if (deb_check(release:"3.0", prefix:"libapache-mod-interchange", reference:"4.8.3.20020306-1.woody.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
