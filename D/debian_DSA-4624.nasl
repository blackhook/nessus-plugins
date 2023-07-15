#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4624. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133731);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2017-1000159", "CVE-2019-1010006", "CVE-2019-11459");
  script_xref(name:"DSA", value:"4624");

  script_name(english:"Debian DSA-4624-1 : evince - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in evince, a simple multi-page
document viewer.

  - CVE-2017-1000159
    Tobias Mueller reported that the DVI exporter in evince
    is susceptible to a command injection vulnerability via
    specially crafted filenames.

  - CVE-2019-11459
    Andy Nguyen reported that the tiff_document_render() and
    tiff_document_get_thumbnail() functions in the TIFF
    document backend did not handle errors from
    TIFFReadRGBAImageOriented(), leading to disclosure of
    uninitialized memory when processing TIFF image files.

  - CVE-2019-1010006
    A buffer overflow vulnerability in the tiff backend
    could lead to denial of service, or potentially the
    execution of arbitrary code if a specially crafted PDF
    file is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=927820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-1010006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/evince"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/evince"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/evince"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4624"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the evince packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 3.22.1-3+deb9u2.

For the stable distribution (buster), these problems have been fixed
in version 3.30.2-3+deb10u1. The stable distribution is only affected
by CVE-2019-11459."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1010006");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evince");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"evince", reference:"3.30.2-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"evince-common", reference:"3.30.2-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-evince-3.0", reference:"3.30.2-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libevdocument3-4", reference:"3.30.2-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libevince-dev", reference:"3.30.2-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libevview3-3", reference:"3.30.2-3+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"browser-plugin-evince", reference:"3.22.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"evince", reference:"3.22.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"evince-common", reference:"3.22.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"evince-gtk", reference:"3.22.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-evince-3.0", reference:"3.22.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libevdocument3-4", reference:"3.22.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libevince-dev", reference:"3.22.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libevview3-3", reference:"3.22.1-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
