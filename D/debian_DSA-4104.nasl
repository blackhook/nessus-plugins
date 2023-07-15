#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4104. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106593);
  script_version("3.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-17969");
  script_xref(name:"DSA", value:"4104");

  script_name(english:"Debian DSA-4104-1 : p7zip - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'landave' discovered a heap-based buffer overflow vulnerability in the
NCompress::NShrink::CDecoder::CodeReal method in p7zip, a 7zr file
archiver with high compression ratio. A remote attacker can take
advantage of this flaw to cause a denial-of-service or, potentially
the execution of arbitrary code with the privileges of the user
running p7zip, if a specially crafted shrinked ZIP archive is
processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=888297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/p7zip"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/p7zip"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/p7zip"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4104"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the p7zip packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 9.20.1~dfsg.1-4.1+deb8u3.

For the stable distribution (stretch), this problem has been fixed in
version 16.02+dfsg-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:p7zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"p7zip", reference:"9.20.1~dfsg.1-4.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"p7zip-full", reference:"9.20.1~dfsg.1-4.1+deb8u3")) flag++;
if (deb_check(release:"9.0", prefix:"p7zip", reference:"16.02+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"p7zip-full", reference:"16.02+dfsg-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
