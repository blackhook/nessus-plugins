#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4349. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119314);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-11613", "CVE-2017-17095", "CVE-2018-10963", "CVE-2018-15209", "CVE-2018-16335", "CVE-2018-17101", "CVE-2018-18557", "CVE-2018-5784", "CVE-2018-7456", "CVE-2018-8905");
  script_xref(name:"DSA", value:"4349");

  script_name(english:"Debian DSA-4349-1 : tiff - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the libtiff library
and the included tools, which may result in denial of service or the
execution of arbitrary code if malformed image files are processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/tiff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/tiff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4349"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tiff packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.0.8-2+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libtiff-doc", reference:"4.0.8-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libtiff-opengl", reference:"4.0.8-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libtiff-tools", reference:"4.0.8-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libtiff5", reference:"4.0.8-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libtiff5-dev", reference:"4.0.8-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libtiffxx5", reference:"4.0.8-2+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
