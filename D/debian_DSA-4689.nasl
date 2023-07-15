#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4689. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136721);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2019-6477", "CVE-2020-8616", "CVE-2020-8617");
  script_xref(name:"DSA", value:"4689");
  script_xref(name:"IAVA", value:"2020-A-0217-S");

  script_name(english:"Debian DSA-4689-1 : bind9 - security update");
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

  - CVE-2019-6477
    It was discovered that TCP-pipelined queries can bypass
    tcp-client limits resulting in denial of service.

  - CVE-2020-8616
    It was discovered that BIND does not sufficiently limit
    the number of fetches performed when processing
    referrals. An attacker can take advantage of this flaw
    to cause a denial of service (performance degradation)
    or use the recursing server in a reflection attack with
    a high amplification factor.

  - CVE-2020-8617
    It was discovered that a logic error in the code which
    checks TSIG validity can be used to trigger an assertion
    failure, resulting in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=945171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-6477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4689"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the bind9 packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 1:9.10.3.dfsg.P4-12.3+deb9u6.

For the stable distribution (buster), these problems have been fixed
in version 1:9.11.5.P4+dfsg-5.1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"bind9", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bind9-doc", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bind9-host", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bind9utils", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"dnsutils", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libbind-dev", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libbind-export-dev", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libbind9-161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libdns-export1104", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libdns-export1104-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libdns1104", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libirs-export161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libirs-export161-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libirs161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisc-export1100", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisc-export1100-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisc1100", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisccc-export161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisccc-export161-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisccc161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisccfg-export163", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisccfg-export163-udeb", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libisccfg163", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"liblwres161", reference:"1:9.11.5.P4+dfsg-5.1+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"bind9", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"bind9-doc", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"bind9-host", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"bind9utils", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"dnsutils", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"host", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libbind-dev", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libbind-export-dev", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libbind9-140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libdns-export162", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libdns-export162-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libdns162", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libirs-export141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libirs-export141-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libirs141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisc-export160", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisc-export160-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisc160", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc-export140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc-export140-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg-export140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg-export140-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"liblwres141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"lwresd", reference:"1:9.10.3.dfsg.P4-12.3+deb9u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
