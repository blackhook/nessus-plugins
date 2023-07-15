#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2313-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139341);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/14");

  script_cve_id("CVE-2020-15861", "CVE-2020-15862");
  script_xref(name:"IAVA", value:"2020-A-0384-S");

  script_name(english:"Debian DLA-2313-1 : net-snmp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A privilege escalation vulnerability was discovered in Net-SNMP, a set
of tools for collecting and organising information about devices on
computer networks, due to incorrect symlink handling (CVE-2020-15861).

This security update also applies an upstream fix to their previous
handling of CVE-2020-15862 as part of DLA-2299-1.

For Debian 9 'Stretch', these problems have been fixed in version
5.7.3+dfsg-1.7+deb9u3.

We recommend that you upgrade your net-snmp packages.

For the detailed security status of net-snmp please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/net-snmp

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/net-snmp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/net-snmp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15862");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp30-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-netsnmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tkmib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/06");
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
if (deb_check(release:"9.0", prefix:"libsnmp-base", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp-dev", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp-perl", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp30", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp30-dbg", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-netsnmp", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"snmp", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"snmpd", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"snmptrapd", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"tkmib", reference:"5.7.3+dfsg-1.7+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
