#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2072-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133105);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-21015", "CVE-2018-21016", "CVE-2019-13618", "CVE-2019-20161", "CVE-2019-20162", "CVE-2019-20163", "CVE-2019-20165", "CVE-2019-20170", "CVE-2019-20171", "CVE-2019-20208");

  script_name(english:"Debian DLA-2072-1 : gpac security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple issues were found in gpac, a multimedia framework featuring
the MP4Box muxer.

CVE-2018-21015

AVC_DuplicateConfig() at isomedia/avc_ext.c allows remote attackers to
cause a denial of service (NULL pointer dereference and application
crash) via a crafted file.

CVE-2018-21016

audio_sample_entry_AddBox() at isomedia/box_code_base.c allows remote
attackers to cause a denial of service (heap-based buffer over-read
and application crash) via a crafted file.

CVE-2019-13618

isomedia/isom_read.c in libgpac.a has a heap-based buffer over-read,
as demonstrated by a crash in gf_m2ts_sync in media_tools/mpegts.c.

CVE-2019-20161

heap-based buffer overflow in the function
ReadGF_IPMPX_WatermarkingInit() in odf/ipmpx_code.c.

CVE-2019-20162

heap-based buffer overflow in the function gf_isom_box_parse_ex() in
isomedia/box_funcs.c.

CVE-2019-20163

NULL pointer dereference in the function gf_odf_avc_cfg_write_bs() in
odf/descriptors.c.

CVE-2019-20165

NULL pointer dereference in the function ilst_item_Read() in
isomedia/box_code_apple.c.

CVE-2019-20170

invalid pointer dereference in the function GF_IPMPX_AUTH_Delete() in
odf/ipmpx_code.c.

CVE-2019-20171

memory leaks in metx_New in isomedia/box_code_base.c and abst_Read in
isomedia/box_code_adobe.c.

CVE-2019-20208

dimC_Read in isomedia/box_code_3gpp.c in GPAC 0.8.0 has a stack-based
buffer overflow.

For Debian 8 'Jessie', these problems have been fixed in version
0.5.0+svn5324~dfsg1-1+deb8u5.

We recommend that you upgrade your gpac packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gpac"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpac-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpac-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpac-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpac3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
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
if (deb_check(release:"8.0", prefix:"gpac", reference:"0.5.0+svn5324~dfsg1-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"gpac-dbg", reference:"0.5.0+svn5324~dfsg1-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"gpac-modules-base", reference:"0.5.0+svn5324~dfsg1-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgpac-dbg", reference:"0.5.0+svn5324~dfsg1-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgpac-dev", reference:"0.5.0+svn5324~dfsg1-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgpac3", reference:"0.5.0+svn5324~dfsg1-1+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
