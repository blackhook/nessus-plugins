#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2234-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137154);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2005-1513", "CVE-2005-1514", "CVE-2005-1515", "CVE-2020-3811", "CVE-2020-3812");

  script_name(english:"Debian DLA-2234-1 : netqmail security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There were several CVE bugs reported against src:netqmail.

CVE-2005-1513

Integer overflow in the stralloc_readyplus function in qmail, when
running on 64 bit platforms with a large amount of virtual memory,
allows remote attackers to cause a denial of service and possibly
execute arbitrary code via a large SMTP request.

CVE-2005-1514

commands.c in qmail, when running on 64 bit platforms with a large
amount of virtual memory, allows remote attackers to cause a denial of
service and possibly execute arbitrary code via a long SMTP command
without a space character, which causes an array to be referenced with
a negative index.

CVE-2005-1515

Integer signedness error in the qmail_put and substdio_put functions
in qmail, when running on 64 bit platforms with a large amount of
virtual memory, allows remote attackers to cause a denial of service
and possibly execute arbitrary code via a large number of SMTP RCPT TO
commands.

CVE-2020-3811

qmail-verify as used in netqmail 1.06 is prone to a mail-address
verification bypass vulnerability.

CVE-2020-3812

qmail-verify as used in netqmail 1.06 is prone to an information
disclosure vulnerability. A local attacker can test for the existence
of files and directories anywhere in the filesystem because
qmail-verify runs as root and tests for the existence of files in the
attacker's home directory, without dropping its privileges first.

For Debian 8 'Jessie', these problems have been fixed in version
1.06-6.2~deb8u1.

We recommend that you upgrade your netqmail packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/netqmail"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected qmail, and qmail-uids-gids packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3811");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qmail-uids-gids");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"qmail", reference:"1.06-6.2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"qmail-uids-gids", reference:"1.06-6.2~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
