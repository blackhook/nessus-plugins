#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2025-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131783);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-2025-1 : openslp-dfsg security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The OpenSLP package had two open security issues :

CVE-2017-17833

OpenSLP releases in the 1.0.2 and 1.1.0 code streams have a
heap-related memory corruption issue which may manifest itself as a
denial of service or a remote code-execution vulnerability.

CVE-2019-5544

OpenSLP as used in ESXi and the Horizon DaaS appliances has a heap
overwrite issue. VMware has evaluated the severity of this issue to be
in the critical severity range.

For Debian 8 'Jessie', these problems have been fixed in version
1.2.1-10+deb8u2. This upload was prepared by Utkarsh Gupta
<guptautkarsh2102@gmail.com>.

We recommend that you upgrade your openslp-dfsg packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openslp-dfsg"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openslp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slptool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libslp-dev", reference:"1.2.1-10+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libslp1", reference:"1.2.1-10+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openslp-doc", reference:"1.2.1-10+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"slpd", reference:"1.2.1-10+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"slptool", reference:"1.2.1-10+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
