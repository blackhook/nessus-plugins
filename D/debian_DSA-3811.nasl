#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3811. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97800);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-5596", "CVE-2017-5597", "CVE-2017-6014", "CVE-2017-6467", "CVE-2017-6468", "CVE-2017-6469", "CVE-2017-6470", "CVE-2017-6471", "CVE-2017-6472", "CVE-2017-6473", "CVE-2017-6474");
  script_xref(name:"DSA", value:"3811");

  script_name(english:"Debian DSA-3811-1 : wireshark - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that wireshark, a network protocol analyzer,
contained several vulnerabilities in the dissectors for ASTERIX,
DHCPv6, NetScaler, LDSS, IAX2, WSP, K12 and STANAG 4607, that could
lead to various crashes, denial-of-service or execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3811"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.12.1+g01b65bf-4+deb8u11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libwireshark-data", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libwireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libwireshark5", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libwiretap-dev", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libwiretap4", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libwsutil-dev", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libwsutil4", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"tshark", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-common", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-dbg", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-doc", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-qt", reference:"1.12.1+g01b65bf-4+deb8u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
