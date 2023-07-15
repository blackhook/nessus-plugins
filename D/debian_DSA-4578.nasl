#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4578. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131439);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2019-9232", "CVE-2019-9325", "CVE-2019-9371", "CVE-2019-9433");
  script_xref(name:"DSA", value:"4578");

  script_name(english:"Debian DSA-4578-1 : libvpx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were found in libvpx multimedia library which
could result in denial of service and potentially the execution of
arbitrary code if malformed WebM files are processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libvpx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libvpx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/libvpx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4578"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvpx packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 1.6.1-3+deb9u2.

For the stable distribution (buster), these problems have been fixed
in version 1.7.0-3+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9232");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvpx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libvpx-dev", reference:"1.7.0-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvpx-doc", reference:"1.7.0-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvpx5", reference:"1.7.0-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vpx-tools", reference:"1.7.0-3+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvpx-dev", reference:"1.6.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libvpx-doc", reference:"1.6.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libvpx4", reference:"1.6.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vpx-tools", reference:"1.6.1-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
