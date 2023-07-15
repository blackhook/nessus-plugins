#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1880-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127862);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-10216");
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"Debian DLA-1880-1 : ghostscript security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Netanel reported that the .buildfont1 procedure in Ghostscript, the
GPL PostScript/PDF interpreter, does not properly restrict privileged
calls, which could result in bypass of file system restrictions of the
dSAFER sandbox.

For Debian 8 'Jessie', this problem has been fixed in version
9.26a~dfsg-0+deb8u4.

We recommend that you upgrade your ghostscript packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00012.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/ghostscript");
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10216");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"8.0", prefix:"ghostscript", reference:"9.26a~dfsg-0+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-dbg", reference:"9.26a~dfsg-0+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-doc", reference:"9.26a~dfsg-0+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-x", reference:"9.26a~dfsg-0+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgs-dev", reference:"9.26a~dfsg-0+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9", reference:"9.26a~dfsg-0+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9-common", reference:"9.26a~dfsg-0+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
