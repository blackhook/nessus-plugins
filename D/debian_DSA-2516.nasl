#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2516. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60142);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-3571", "CVE-2012-3954");
  script_bugtraq_id(54665);
  script_xref(name:"DSA", value:"2516");

  script_name(english:"Debian DSA-2516-1 : isc-dhcp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities affecting ISC dhcpd, a server for
automatic IP address assignment, in Debian have been discovered.

  - CVE-2012-3571
    Markus Hietava of the Codenomicon CROSS project
    discovered that it is possible to force the server to
    enter an infinite loop via messages with malformed
    client identifiers.

  - CVE-2012-3954
    Glen Eustace discovered that DHCP servers running in
    DHCPv6 mode and possibly DHCPv4 mode suffer of memory
    leaks while processing messages. An attacker can use
    this flaw to exhaust resources and perform denial of
    service attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/isc-dhcp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2012/dsa-2516"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the isc-dhcp packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"dhcp3-client", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-common", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-dev", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-relay", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-server", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-dbg", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-udeb", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-common", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-dev", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay-dbg", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-dbg", reference:"4.1.1-P1-15+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-ldap", reference:"4.1.1-P1-15+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
