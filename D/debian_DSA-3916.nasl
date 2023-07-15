#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3916. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101910);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000083");
  script_xref(name:"DSA", value:"3916");

  script_name(english:"Debian DSA-3916-1 : atril - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Atril, the MATE document viewer, made insecure
use of tar when opening tar comic book archives (CBT). Opening a
malicious CBT archive could result in the execution of arbitrary code.
This update disables the CBT format entirely."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=868500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/atril"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/atril"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3916"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the atril packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.8.1+dfsg1-4+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.16.1-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Evince CBT File Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:atril");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"8.0", prefix:"atril", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"atril-common", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"atril-dbg", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatrildocument-dev", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatrildocument3", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatrildocument3-dbg", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatrilview-dev", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatrilview3", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatrilview3-dbg", reference:"1.8.1+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"atril", reference:"1.16.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"atril-common", reference:"1.16.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-atril", reference:"1.16.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libatrildocument-dev", reference:"1.16.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libatrildocument3", reference:"1.16.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libatrilview-dev", reference:"1.16.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libatrilview3", reference:"1.16.1-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
