#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4746. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139631);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/17");

  script_cve_id("CVE-2020-15861", "CVE-2020-15862");
  script_xref(name:"DSA", value:"4746");
  script_xref(name:"IAVA", value:"2020-A-0384-S");

  script_name(english:"Debian DSA-4746-1 : net-snmp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in net-snmp, a suite of Simple
Network Management Protocol applications, which could lead to
privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=965166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=966599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/net-snmp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/net-snmp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4746"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the net-snmp packages.

For the stable distribution (buster), these problems have been fixed
in version 5.7.3+dfsg-5+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libsnmp-base", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsnmp-dev", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsnmp-perl", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsnmp30", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsnmp30-dbg", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python-netsnmp", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"snmp", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"snmpd", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"snmptrapd", reference:"5.7.3+dfsg-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"tkmib", reference:"5.7.3+dfsg-5+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
