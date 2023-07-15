#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4015. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104365);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");
  script_xref(name:"DSA", value:"4015");

  script_name(english:"Debian DSA-4015-1 : openjdk-8 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in impersonation
of Kerberos services, denial of service, sandbox bypass or HTTP header
injection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openjdk-8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4015"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-8 packages.

For the stable distribution (stretch), these problems have been fixed
in version 8u151-b12-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");
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
if (deb_check(release:"9.0", prefix:"openjdk-8-dbg", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-demo", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-doc", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jdk", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jdk-headless", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jre", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jre-headless", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jre-zero", reference:"8u151-b12-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-source", reference:"8u151-b12-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
