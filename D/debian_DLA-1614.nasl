#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1614-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119849);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-14423", "CVE-2018-6616");

  script_name(english:"Debian DLA-1614-1 : openjpeg2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in openjpeg2, the
open-source JPEG 2000 codec.

CVE-2018-6616

Excessive iteration in the opj_t1_encode_cblks function
(openjp2/t1.c). Remote attackers could leverage this vulnerability to
cause a denial of service via a crafted bmp file.

CVE-2018-14423

Division-by-zero vulnerabilities in the functions pi_next_pcrl,
pi_next_cprl, and pi_next_rpcl in (lib/openjp3d/pi.c). Remote
attackers could leverage this vulnerability to cause a denial of
service (application crash).

For Debian 8 'Jessie', these problems have been fixed in version
2.1.0-2+deb8u6.

We recommend that you upgrade your openjpeg2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openjpeg2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-dec-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libopenjp2-7", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dbg", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dev", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-tools", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d-tools", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d7", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-dec-server", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-server", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-viewer", reference:"2.1.0-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip7", reference:"2.1.0-2+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
