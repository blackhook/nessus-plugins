#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4694. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136933);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2020-12662", "CVE-2020-12663");
  script_xref(name:"DSA", value:"4694");

  script_name(english:"Debian DSA-4694-1 : unbound - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two vulnerabiliites have been discovered in Unbound, a recursive-only
caching DNS server; a traffic amplification attack against third-party
authoritative name servers (NXNSAttack) and insufficient sanitisation
of replies from upstream servers could result in denial of service via
an infinite loop.

The version of Unbound in the oldstable distribution (stretch) is no
longer supported. If these security issues affect your setup, you
should upgrade to the stable distribution (buster)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/unbound"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/unbound"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4694"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the unbound packages.

For the stable distribution (buster), these problems have been fixed
in version 1.9.0-2+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/28");
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
if (deb_check(release:"10.0", prefix:"libunbound-dev", reference:"1.9.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libunbound8", reference:"1.9.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"python-unbound", reference:"1.9.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"python3-unbound", reference:"1.9.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"unbound", reference:"1.9.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"unbound-anchor", reference:"1.9.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"unbound-host", reference:"1.9.0-2+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
