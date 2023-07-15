#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4548. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130136);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-2894", "CVE-2019-2945", "CVE-2019-2949", "CVE-2019-2962", "CVE-2019-2964", "CVE-2019-2973", "CVE-2019-2975", "CVE-2019-2978", "CVE-2019-2981", "CVE-2019-2983", "CVE-2019-2987", "CVE-2019-2988", "CVE-2019-2989", "CVE-2019-2992", "CVE-2019-2999");
  script_xref(name:"DSA", value:"4548");

  script_name(english:"Debian DSA-4548-1 : openjdk-8 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the OpenJDK Java
runtime, resulting in cross-site scripting, denial of service,
information disclosure or Kerberos user impersonation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openjdk-8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openjdk-8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4548"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the openjdk-8 packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 8u232-b09-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2975");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"openjdk-8-dbg", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-demo", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-doc", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jdk", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jdk-headless", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jre", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jre-headless", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-jre-zero", reference:"8u232-b09-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openjdk-8-source", reference:"8u232-b09-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
