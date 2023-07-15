#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4314. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118071);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-18065");
  script_xref(name:"DSA", value:"4314");

  script_name(english:"Debian DSA-4314-1 : net-snmp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Magnus Klaaborg Stubman discovered a NULL pointer dereference bug in
net-snmp, a suite of Simple Network Management Protocol applications,
allowing a remote, authenticated attacker to crash the snmpd process
(causing a denial of service)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=910638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/net-snmp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/net-snmp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4314"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the net-snmp packages.

For the stable distribution (stretch), this problem has been fixed in
version 5.7.3+dfsg-1.7+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/12");
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
if (deb_check(release:"9.0", prefix:"libsnmp-base", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp-dev", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp-perl", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp30", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp30-dbg", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-netsnmp", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"snmp", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"snmpd", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"snmptrapd", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tkmib", reference:"5.7.3+dfsg-1.7+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
