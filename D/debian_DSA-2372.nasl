#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2372. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57512);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-4862");
  script_xref(name:"DSA", value:"2372");

  script_name(english:"Debian DSA-2372-1 : heimdal - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Kerberos support for telnetd contains a
pre-authentication buffer overflow, which may enable remote attackers
who can connect to TELNET to execute arbitrary code with root
privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/heimdal"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2372"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the heimdal packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.2.dfsg.1-2.1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.0~git20100726.dfsg.1-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
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
if (deb_check(release:"5.0", prefix:"heimdal", reference:"1.2.dfsg.1-2.1+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-clients", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-clients-x", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-dbg", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-dev", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-docs", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-kcm", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-kdc", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-multidev", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-servers", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"heimdal-servers-x", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libasn1-8-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libgssapi2-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libhdb9-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libheimntlm0-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libhx509-5-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libkadm5clnt7-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libkadm5srv8-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libkafs0-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libkdc2-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb5-26-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libotp0-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libroken18-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libsl0-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libwind0-heimdal", reference:"1.4.0~git20100726.dfsg.1-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
