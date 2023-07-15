#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3910. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101555);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-11104");
  script_xref(name:"DSA", value:"3910");

  script_name(english:"Debian DSA-3910-1 : knot - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Clement Berthaux from Synaktiv discovered a signature forgery
vulnerability in knot, an authoritative-only DNS server. This
vulnerability allows an attacker to bypass TSIG authentication by
sending crafted DNS packets to a server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=865678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/knot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/knot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3910"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the knot packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.6.0-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 2.4.0-3+deb9u1.

For the testing (buster) and unstable (sid), this problem will be
fixed in a later update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:knot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");
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
if (deb_check(release:"8.0", prefix:"knot", reference:"1.6.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"knot-dbg", reference:"1.6.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"knot-dnsutils", reference:"1.6.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"knot-doc", reference:"1.6.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"knot-host", reference:"1.6.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"knot-libs", reference:"1.6.0-1+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"knot", reference:"2.4.0-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"knot-dnsutils", reference:"2.4.0-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"knot-doc", reference:"2.4.0-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"knot-host", reference:"2.4.0-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libdnssec2", reference:"2.4.0-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libknot-dev", reference:"2.4.0-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libknot5", reference:"2.4.0-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libzscanner1", reference:"2.4.0-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
