#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1024-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101535);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-7529");

  script_name(english:"Debian DLA-1024-1 : nginx security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was vulnerability in the range filter of
nginx, a web/proxy server. A specially crafted request might result in
an integer overflow and incorrect processing of HTTP ranges,
potentially resulting in a sensitive information leak.

For Debian 7 'Wheezy', this issue has been fixed in nginx version
1.2.1-2.2+wheezy4+deb7u1.

We recommend that you upgrade your nginx packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nginx"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-extras-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-full-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-light-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-naxsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-naxsi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-naxsi-ui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/14");
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
if (deb_check(release:"7.0", prefix:"nginx", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-common", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-doc", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-extras", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-extras-dbg", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-full", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-full-dbg", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-light", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-light-dbg", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi-dbg", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi-ui", reference:"1.2.1-2.2+wheezy4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
