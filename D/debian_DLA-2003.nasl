#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2003-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131248);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-2774");

  script_name(english:"Debian DLA-2003-1 : isc-dhcp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue has been found in isc-dhcp, a server for automatic IP address
assignment.

The number of simultaneous open TCP connections to OMAPI port of the
server has to be limited to 200 in order to avoid a denial of service.

For Debian 8 'Jessie', this problem has been fixed in version
4.3.1-6+deb8u4.

We recommend that you upgrade your isc-dhcp packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/isc-dhcp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"isc-dhcp-client", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-client-dbg", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-client-udeb", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-common", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-dbg", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-dev", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-relay", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-relay-dbg", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-server", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-server-dbg", reference:"4.3.1-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"isc-dhcp-server-ldap", reference:"4.3.1-6+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
