#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2216. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53343);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-0997");
  script_bugtraq_id(47176);
  script_xref(name:"DSA", value:"2216");

  script_name(english:"Debian DSA-2216-1 : isc-dhcp - missing input sanitization");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sebastian Krahmer and Marius Tomaschewski discovered that dhclient of
isc-dhcp, a DHCP client, is not properly filtering shell
meta-characters in certain options in DHCP server responses. These
options are reused in an insecure fashion by dhclient scripts. This
allows an attacker to execute arbitrary commands with the privileges
of such a process by sending crafted DHCP options to a client using a
rogue server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=621099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/isc-dhcp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2216"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the isc-dhcp packages.

For the oldstable distribution (lenny), this problem has been fixed in
additional update for dhcp3.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"dhcp3-client", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-common", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-dev", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-relay", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-server", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-dbg", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-udeb", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-common", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-dev", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay-dbg", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-dbg", reference:"4.1.1-P1-15+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-ldap", reference:"4.1.1-P1-15+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
