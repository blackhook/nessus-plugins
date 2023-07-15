#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2176-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136630);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-10188");
  script_xref(name:"IAVA", value:"2020-A-0293");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DLA-2176-1 : inetutils security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"NOTE: This DLA was intially sent on 2020-04-14 but for reasons unknown
failed to reach the mailing list. It is being re-sent now to ensure
that it appears in the mailing list archive. No new version of
inetutils has been published since version 2:1.9.2.39.3a460-3+deb8u1
described in the original advisory.

A vulnerability was discovered in the telnetd component of inetutils,
a collection of network utilities. Execution of arbitrary remote code
was possible through short writes or urgent data.

For Debian 8 'Jessie', this problem has been fixed in version
2:1.9.2.39.3a460-3+deb8u1.

We recommend that you upgrade your inetutils packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00012.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/inetutils");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-inetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-syslogd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-talk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-talkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-traceroute");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"inetutils-ftp", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-ftpd", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-inetd", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-ping", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-syslogd", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-talk", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-talkd", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-telnet", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-telnetd", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-tools", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"inetutils-traceroute", reference:"2:1.9.2.39.3a460-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
