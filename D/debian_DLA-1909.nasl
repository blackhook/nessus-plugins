#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1909-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128509);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-9381", "CVE-2015-9382", "CVE-2015-9383");

  script_name(english:"Debian DLA-1909-1 : freetype security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several newly-referenced issues have been fixed in the FreeType 2 font
engine.

CVE-2015-9381

heap-based buffer over-read in T1_Get_Private_Dict in type1/t1parse.c

CVE-2015-9382

buffer over-read in skip_comment in psaux/psobjs.c because
ps_parser_skip_PS_token is mishandled in an FT_New_Memory_Face
operation

CVE-2015-9383

a heap-based buffer over-read in tt_cmap14_validate in sfnt/ttcmap.c

For Debian 8 'Jessie', these problems have been fixed in version
2.5.2-3+deb8u4.

We recommend that you upgrade your freetype packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/freetype"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype2-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreetype6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreetype6-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/05");
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
if (deb_check(release:"8.0", prefix:"freetype2-demos", reference:"2.5.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libfreetype6", reference:"2.5.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libfreetype6-dev", reference:"2.5.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libfreetype6-udeb", reference:"2.5.2-3+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
