#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-148. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14985);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2001-0387", "CVE-2001-1034", "CVE-2002-1049", "CVE-2002-1050");
  script_bugtraq_id(3357, 5348, 5349);
  script_xref(name:"DSA", value:"148");

  script_name(english:"Debian DSA-148-1 : hylafax - buffer overflows and format string vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A set of problems have been discovered in Hylafax, a flexible
client/server fax software distributed with many GNU/Linux
distributions. Quoting SecurityFocus the problems are in detail :

  - A format string vulnerability makes it possible for
    users to potentially execute arbitrary code on some
    implementations. Due to insufficient checking of input,
    it's possible to execute a format string attack. Since
    this only affects systems with the faxrm and faxalter
    programs installed setuid, Debian is not vulnerable.
  - A buffer overflow has been reported in Hylafax. A
    malicious fax transmission may include a long scan line
    that will overflow a memory buffer, corrupting adjacent
    memory. An exploit may result in a denial of service
    condition, or possibly the execution of arbitrary code
    with root privileges.

  - A format string vulnerability has been discovered in
    faxgetty. Incoming fax messages include a Transmitting
    Subscriber Identification (TSI) string, used to identify
    the sending fax machine. Hylafax uses this data as part
    of a format string without properly sanitizing the
    input. Malicious fax data may cause the server to crash,
    resulting in a denial of service condition.

  - Marcin Dawcewicz discovered a format string
    vulnerability in hfaxd, which will crash hfaxd under
    certain circumstances. Since Debian doesn't have hfaxd
    installed setuid root, this problem cannot directly lead
    into a vulnerability. This has been fixed by Darren
    Nickerson, which was already present in newer versions,
    but not in the potato version.

These problems have been fixed in version 4.0.2-14.3 for the old
stable distribution (potato), in version 4.1.1-1.1 for the current
stable distribution (woody) and in version 4.1.2-2.1 for the unstable
distribution (sid)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-148"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the hylafax packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hylafax");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"hylafax-client", reference:"4.0.2-14.3")) flag++;
if (deb_check(release:"2.2", prefix:"hylafax-doc", reference:"4.0.2-14.3")) flag++;
if (deb_check(release:"2.2", prefix:"hylafax-server", reference:"4.0.2-14.3")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-client", reference:"4.1.1-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-doc", reference:"4.1.1-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-server", reference:"4.1.1-1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
