#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4299. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117674);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/16 15:19:25");

  script_cve_id("CVE-2018-17407");
  script_xref(name:"DSA", value:"4299");

  script_name(english:"Debian DSA-4299-1 : texlive-bin - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nick Roessler from the University of Pennsylvania has found a buffer
overflow in texlive-bin, the executables for TexLive, the popular
distribution of TeX document production system.

This buffer overflow can be used for arbitrary code execution by
crafting a special type1 font (.pfb) and provide it to users running
pdf(la)tex, dvips or luatex in a way that the font is loaded."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=909317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/texlive-bin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/texlive-bin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4299"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the texlive-bin packages.

For the stable distribution (stretch), this problem has been fixed in
version 2016.20160513.41080.dfsg-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
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
if (deb_check(release:"9.0", prefix:"libkpathsea-dev", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkpathsea6", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libptexenc-dev", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libptexenc1", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsynctex-dev", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsynctex1", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtexlua52", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtexlua52-dev", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtexluajit-dev", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtexluajit2", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"texlive-binaries", reference:"2016.20160513.41080.dfsg-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
