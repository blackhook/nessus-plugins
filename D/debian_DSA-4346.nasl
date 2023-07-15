#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4346. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119269);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/05");

  script_cve_id("CVE-2018-19134", "CVE-2018-19409", "CVE-2018-19475", "CVE-2018-19476", "CVE-2018-19477", "CVE-2018-19478");
  script_xref(name:"DSA", value:"4346");

  script_name(english:"Debian DSA-4346-1 : ghostscript - security update");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Ghostscript, the GPL
PostScript/PDF interpreter, which may result in denial of service or
the execution of arbitrary code if a malformed Postscript file is
processed (despite the -dSAFER sandbox being enabled).

This update rebases ghostscript for stretch to the upstream version
9.26 which includes additional changes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ghostscript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ghostscript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4346"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ghostscript packages.

For the stable distribution (stretch), these problems have been fixed
in version 9.26~dfsg-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19409");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");

var flag = 0;
if (deb_check(release:"9.0", prefix:"ghostscript", reference:"9.26~dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-dbg", reference:"9.26~dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-doc", reference:"9.26~dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-x", reference:"9.26~dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgs-dev", reference:"9.26~dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgs9", reference:"9.26~dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgs9-common", reference:"9.26~dfsg-0+deb9u1")) flag++;

if (flag)
  security_report_v4(port:0, extra:deb_report_get(), severity:SECURITY_HOLE);

else audit(AUDIT_HOST_NOT, "affected");
