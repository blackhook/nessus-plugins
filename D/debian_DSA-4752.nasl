#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4752. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139930);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2020-8619",
    "CVE-2020-8622",
    "CVE-2020-8623",
    "CVE-2020-8624"
  );
  script_xref(name:"DSA", value:"4752");
  script_xref(name:"IAVA", value:"2020-A-0385-S");

  script_name(english:"Debian DSA-4752-1 : bind9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in BIND, a DNS server
implementation.

  - CVE-2020-8619
    It was discovered that an asterisk character in an empty
    non terminal can cause an assertion failure, resulting
    in denial of service.

  - CVE-2020-8622
    Dave Feldman, Jeff Warren, and Joel Cunningham reported
    that a truncated TSIG response can lead to an assertion
    failure, resulting in denial of service.

  - CVE-2020-8623
    Lyu Chiy reported that a flaw in the native PKCS#11 code
    can lead to a remotely triggerable assertion failure,
    resulting in denial of service.

  - CVE-2020-8624
    Joop Boonen reported that update-policy rules of type
    'subdomain' are enforced incorrectly, allowing updates
    to all parts of the zone along with the intended
    subdomain."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=966497");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-8619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-8622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-8623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-8624");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/bind9");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/bind9");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4752");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the bind9 packages.

For the stable distribution (buster), these problems have been fixed
in version 1:9.11.5.P4+dfsg-5.1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8624");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"bind9", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"bind9-doc", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"bind9-host", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"bind9utils", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dnsutils", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libbind-dev", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libbind-export-dev", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libbind9-161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libdns-export1104", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libdns-export1104-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libdns1104", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libirs-export161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libirs-export161-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libirs161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisc-export1100", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisc-export1100-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisc1100", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisccc-export161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisccc-export161-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisccc161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisccfg-export163", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisccfg-export163-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libisccfg163", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"liblwres161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
