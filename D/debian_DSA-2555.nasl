#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2555. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62440);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");
  script_bugtraq_id(55331, 55676);
  script_xref(name:"DSA", value:"2555");

  script_name(english:"Debian DSA-2555-1 : libxslt - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nicholas Gregoire and Cris Neckar discovered several memory handling
bugs in libxslt, which could lead to denial of service or the
execution of arbitrary code if a malformed document is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxslt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2012/dsa-2555"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxslt packages.

For the stable distribution (squeeze), these problems have been fixed
in version 1.1.26-6+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"libxslt1-dbg", reference:"1.1.26-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libxslt1-dev", reference:"1.1.26-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libxslt1.1", reference:"1.1.26-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxslt1", reference:"1.1.26-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxslt1-dbg", reference:"1.1.26-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"xsltproc", reference:"1.1.26-6+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
