#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-990. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22856);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0670");
  script_xref(name:"DSA", value:"990");

  script_name(english:"Debian DSA-990-1 : bluez-hcidump - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service condition has been discovered in bluez-hcidump, a
utility that analyses Bluetooth HCI packets, which can be triggered
remotely."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=351881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-990"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bluez-hcidump package.

The old stable distribution (woody) does not contain bluez-hcidump
packages.

For the stable distribution (sarge) this problem has been fixed in
version 1.17-1sarge1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-hcidump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"bluez-hcidump", reference:"1.17-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
