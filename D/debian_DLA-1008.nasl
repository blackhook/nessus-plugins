#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1008-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101174);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-7375", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");

  script_name(english:"Debian DLA-1008-1 : libxml2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-7375 Missing validation for external entities in
xmlParsePEReference

CVE-2017-9047 CVE-2017-9048 A buffer overflow was discovered in
libxml2 20904-GITv2.9.4-16-g0741801. The function
xmlSnprintfElementContent in valid.c is supposed to recursively dump
the element content definition into a char buffer 'buf' of size
'size'. The variable len is assigned strlen(buf). If the content->type
is XML_ELEMENT_CONTENT_ELEMENT, then (i) the content->prefix is
appended to buf (if it actually fits) whereupon (ii) content->name is
written to the buffer. However, the check for whether the
content->name actually fits also uses 'len' rather than the updated
buffer length strlen(buf). This allows us to write about 'size' many
bytes beyond the allocated memory. This vulnerability causes programs
that use libxml2, such as PHP, to crash.

CVE-2017-9049 CVE-2017-9050 libxml2 20904-GITv2.9.4-16-g0741801 is
vulnerable to a heap-based buffer over-read in the
xmlDictComputeFastKey function in dict.c. This vulnerability causes
programs that use libxml2, such as PHP, to crash. This vulnerability
exists because of an incomplete fix for libxml2 Bug 759398.

For Debian 7 'Wheezy', these problems have been fixed in version
2.8.0+dfsg1-7+wheezy8.

We recommend that you upgrade your libxml2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libxml2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libxml2", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-dbg", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-dev", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-doc", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-utils", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-utils-dbg", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;
if (deb_check(release:"7.0", prefix:"python-libxml2", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;
if (deb_check(release:"7.0", prefix:"python-libxml2-dbg", reference:"2.8.0+dfsg1-7+wheezy8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
