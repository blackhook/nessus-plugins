#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4359. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119892);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-12086", "CVE-2018-18225", "CVE-2018-18226", "CVE-2018-18227", "CVE-2018-19622", "CVE-2018-19623", "CVE-2018-19624", "CVE-2018-19625", "CVE-2018-19626", "CVE-2018-19627", "CVE-2018-19628");
  script_xref(name:"DSA", value:"4359");

  script_name(english:"Debian DSA-4359-1 : wireshark - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Wireshark, a network
protocol analyzer, which could result in denial of service or the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4359"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.6.5-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libwireshark-data", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwireshark-dev", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwireshark8", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwiretap-dev", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwiretap6", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwscodecs1", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwsutil-dev", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwsutil7", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tshark", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-common", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-dev", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-doc", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-gtk", reference:"2.6.5-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wireshark-qt", reference:"2.6.5-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
