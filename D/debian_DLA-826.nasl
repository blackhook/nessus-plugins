#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-826-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97231);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-6014");

  script_name(english:"Debian DLA-826-1 : wireshark security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was denial of service vulnerability in
wireshark, a network traffic analyzer.

A malformed NATO Ground Moving Target Indicator Format ('STANAG 4607')
capture file could cause a memory exhausion/infinite loop.

For Debian 7 'Wheezy', this issue has been fixed in wireshark version
1.12.1+g01b65bf-4+deb8u6~deb7u6.

We recommend that you upgrade your wireshark packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wireshark"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libwireshark-data", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark2", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap2", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil2", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"tshark", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-common", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dbg", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-doc", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
