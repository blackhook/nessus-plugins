#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4605. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133108);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/24");

  script_cve_id("CVE-2020-2583", "CVE-2020-2590", "CVE-2020-2593", "CVE-2020-2601", "CVE-2020-2604", "CVE-2020-2654", "CVE-2020-2655");
  script_xref(name:"DSA", value:"4605");

  script_name(english:"Debian DSA-4605-1 : openjdk-11 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the OpenJDK Java
runtime, resulting in denial of service, incorrect implementation of
Kerberos GSSAPI and TGS requests or incorrect TLS handshakes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openjdk-11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/openjdk-11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4605"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-11 packages.

For the stable distribution (buster), these problems have been fixed
in version 11.0.6+10-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
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
if (deb_check(release:"10.0", prefix:"openjdk-11-dbg", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-demo", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-doc", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-jdk", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-jdk-headless", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-jre", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-jre-headless", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-jre-zero", reference:"11.0.6+10-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openjdk-11-source", reference:"11.0.6+10-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
