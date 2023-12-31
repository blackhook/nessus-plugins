#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2648. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65582);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-5529", "CVE-2013-2492");
  script_bugtraq_id(56521, 58393);
  script_xref(name:"DSA", value:"2648");

  script_name(english:"Debian DSA-2648-1 : firebird2.5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow was discovered in the Firebird database server,
which could result in the execution of arbitrary code. In addition, a
denial of service vulnerability was discovered in the TraceManager."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/firebird2.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2013/dsa-2648"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the firebird2.5 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firebird Relational Database CNCT Group Number Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"firebird2.5-classic", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-classic-common", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-common", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-common-doc", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-dev", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-doc", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-examples", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-server-common", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-super", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.5-superclassic", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libfbclient2", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libfbembed2.5", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libib-util", reference:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
