#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4360. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119893);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2017-14166", "CVE-2017-14501", "CVE-2017-14502", "CVE-2017-14503", "CVE-2018-1000877", "CVE-2018-1000878", "CVE-2018-1000880");
  script_xref(name:"DSA", value:"4360");

  script_name(english:"Debian DSA-4360-1 : libarchive - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were found in libarchive, a multi-format
archive and compression library: Processing malformed RAR archives
could result in denial of service or the execution of arbitrary code
and malformed WARC, LHarc, ISO, Xar or CAB archives could result in
denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libarchive"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libarchive"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4360"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libarchive packages.

For the stable distribution (stretch), these problems have been fixed
in version 3.2.2-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"bsdcpio", reference:"3.2.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bsdtar", reference:"3.2.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libarchive-dev", reference:"3.2.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libarchive-tools", reference:"3.2.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libarchive13", reference:"3.2.2-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
