#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1313-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108569);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-5732", "CVE-2018-5733");
  script_xref(name:"IAVB", value:"2018-B-0034-S");

  script_name(english:"Debian DLA-1313-1 : isc-dhcp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the ISC DHCP client,
relay and server. The Common Vulnerabilities and Exposures project
identifies the following issues :

CVE-2018-5732

Felix Wilhelm of the Google Security Team discovered that the DHCP
client is prone to an out-of-bound memory access vulnerability when
processing specially constructed DHCP options responses, resulting in
potential execution of arbitrary code by a malicious DHCP server.

CVE-2018-5733

Felix Wilhelm of the Google Security Team discovered that the DHCP
server does not properly handle reference counting when processing
client requests. A malicious client can take advantage of this flaw to
cause a denial of service (dhcpd crash) by sending large amounts of
traffic.

For Debian 7 'Wheezy', these problems have been fixed in version
4.2.2.dfsg.1-5+deb70u9.

We recommend that you upgrade your isc-dhcp packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/isc-dhcp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"isc-dhcp-client", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-client-dbg", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-client-udeb", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-common", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-dev", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-relay", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-relay-dbg", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-server", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-server-dbg", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;
if (deb_check(release:"7.0", prefix:"isc-dhcp-server-ldap", reference:"4.2.2.dfsg.1-5+deb70u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
