#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1012-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101211);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-2295");

  script_name(english:"Debian DLA-1012-1 : puppet security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Versions of Puppet prior to 4.10.1 will deserialize data off the wire
(from the agent to the server, in this case) with a attacker-specified
format. This could be used to force YAML deserialization in an unsafe
manner, which would lead to remote code execution.

For Debian 7 'Wheezy', these problems have been fixed in version
2.7.23-1~deb7u4, by enabling PSON serialization on clients and
refusing non-PSON formats on the server.

We recommend that you upgrade your puppet packages. Make sure you
update all your clients before you update the server otherwise older
clients won't be able to connect to the server.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/puppet"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppetmaster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppetmaster-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppetmaster-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/05");
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
if (deb_check(release:"7.0", prefix:"puppet", reference:"2.7.23-1~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-common", reference:"2.7.23-1~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-el", reference:"2.7.23-1~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-testsuite", reference:"2.7.23-1~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster", reference:"2.7.23-1~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster-common", reference:"2.7.23-1~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster-passenger", reference:"2.7.23-1~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"vim-puppet", reference:"2.7.23-1~deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
