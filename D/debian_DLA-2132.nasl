#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2132-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134242);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-18900");

  script_name(english:"Debian DLA-2132-1 : libzypp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was an issue where incorrect default
permissions on a HTTP cookie store could have allowed local attackers
to read private credentials.

For Debian 8 'Jessie', this issue has been fixed in libzypp version
14.29.1-2+deb8u1.

We recommend that you upgrade your libzypp packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libzypp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzypp-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzypp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzypp-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzypp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzypp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzypp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");
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
if (deb_check(release:"8.0", prefix:"libzypp", reference:"14.29.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libzypp-bin", reference:"14.29.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libzypp-common", reference:"14.29.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libzypp-config", reference:"14.29.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libzypp-dbg", reference:"14.29.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libzypp-dev", reference:"14.29.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libzypp-doc", reference:"14.29.1-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
