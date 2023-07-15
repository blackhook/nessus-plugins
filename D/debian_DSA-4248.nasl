#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4248. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111140);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2017-12081", "CVE-2017-12082", "CVE-2017-12086", "CVE-2017-12099", "CVE-2017-12100", "CVE-2017-12101", "CVE-2017-12102", "CVE-2017-12103", "CVE-2017-12104", "CVE-2017-12105", "CVE-2017-2899", "CVE-2017-2900", "CVE-2017-2901", "CVE-2017-2902", "CVE-2017-2903", "CVE-2017-2904", "CVE-2017-2905", "CVE-2017-2906", "CVE-2017-2907", "CVE-2017-2908", "CVE-2017-2918");
  script_xref(name:"DSA", value:"4248");

  script_name(english:"Debian DSA-4248-1 : blender - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in various parsers of
Blender, a 3D modeller/ renderer. Malformed .blend model files and
malformed multimedia files (AVI, BMP, HDR, CIN, IRIS, PNG, TIFF) may
result in the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/blender"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/blender"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4248"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the blender packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.79.b+dfsg0-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:blender");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"9.0", prefix:"blender", reference:"2.79.b+dfsg0-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"blender-data", reference:"2.79.b+dfsg0-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"blender-dbg", reference:"2.79.b+dfsg0-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
