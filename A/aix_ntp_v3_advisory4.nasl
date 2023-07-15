#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102321);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2015-5219",
    "CVE-2015-7691",
    "CVE-2015-7692",
    "CVE-2015-7701",
    "CVE-2015-7702",
    "CVE-2015-7850",
    "CVE-2015-7853",
    "CVE-2015-7855"
  );
  script_bugtraq_id(
    76473,
    77273,
    77274,
    77279,
    77281,
    77283,
    77285,
    77286
  );
  script_xref(name:"TRA", value:"TRA-2015-04");
  script_xref(name:"EDB-ID", value:"40840");

  script_name(english:"AIX NTP v3 Advisory : ntp_advisory4.asc (IV79942) (IV79943) (IV79944) (IV79945) (IV79946)");
  script_summary(english:"Checks the version of the ntp packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NTP installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of Network Time Protocol (NTP)
installed that is affected by the following vulnerabilities :

  - A divide-by-zero error exists in file include/ntp.h
    when handling LOGTOD and ULOGTOD macros in a crafted
    NTP packet. An unauthenticated, remote attacker can
    exploit this, via crafted NTP packets, to crash ntpd.
    (CVE 2015-5219)

  - A flaw exists in the ntp_crypto.c file due to improper
    validation of the 'vallen' value in extension fields. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted autokey packets, to disclose
    sensitive information or cause a denial of service.
    (CVE-2015-7691)

  - A denial of service vulnerability exists in the autokey
    functionality due to a failure in the crypto_bob2(),
    crypto_bob3(), and cert_sign() functions to properly
    validate the 'vallen' value. An unauthenticated, remote
    attacker can exploit this, via specially crafted autokey
    packets, to crash the NTP service. (CVE-2015-7692)

  - A denial of service vulnerability exists in the
    crypto_recv() function in the file ntp_crypto.c related
    to autokey functionality. An unauthenticated, remote
    attacker can exploit this, via an ongoing flood of NTPv4
    autokey requests, to exhaust memory resources.
    (CVE-2015-7701)

  - A denial of service vulnerability exists due to improper
    validation of packets containing certain autokey
    operations. An unauthenticated, remote attacker can
    exploit this, via specially crafted autokey packets,
    to crash the NTP service. (CVE-2015-7702)

  - A denial of service vulnerability exists due to a logic
    flaw in the authreadkeys() function in the file
    authreadkeys.c when handling extended logging where the
    log and key files are set to be the same file. An
    authenticated, remote attacker can exploit this, via a
    crafted set of remote configuration requests, to cause
    the NTP service to stop responding. (CVE-2015-7850)

  - A overflow condition exists in the
    read_refclock_packet() function in the file ntp_io.c
    when handling negative data lengths. A local attacker
    can exploit this to crash the NTP service or possibly
    gain elevated privileges. (CVE-2015-7853)

  - A denial of service vulnerability exists due to an
    assertion flaw in the decodenetnum() function in the
    file decodenetnum.c when handling long data values in
    mode 6 and 7 packets. An unauthenticated, remote
    attacker can exploit this to crash the NTP service.
    (CVE-2015-7855)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/ntp_advisory4.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = oslevel - "AIX-";

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

aix_ntp_vulns = {
  "5.3": {
    "12": {
      "09": {
        "bos.net.tcp.client": {
          "minfilesetver":"5.3.12.0",
          "maxfilesetver":"5.3.12.10",
          "patch":"(IV79946s9a|IV84269m9a|IV87614m9a|IV92194m9a|IV96305m9a)"
        }
      }
    }
  },
  "6.1": {
    "09": {
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.101",
          "patch":"(IV79942s6a|IV83984m6a|IV87419m6a|IV91803m6a)"
        }
      }
    }
  },
  "7.1": {
    "03": {
      "05": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.45",
          "patch":"(IV79943s5b|IV83993m5a|IV87615m5a|IV92193m5a)"
        }
      }
    },
    "04": {
      "01": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.0",
          "patch":"(IV79944s1a|IV83994m1a|IV87420m0a|IV91951m3a)"
        }
      }
    }
  },
  "7.2": {
   "00": {
      "01": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.0",
          "patch":"(IV79945s1a|IV83995m1a|IV87939m0b|IV92192m2a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.0",
          "patch":"(IV79945s1a|IV83995m1a|IV87939m0b|IV92192m2a)"
        }
      }
    }
  }
};

version_report = "AIX " + oslevel;
if ( empty_or_null(aix_ntp_vulns[oslevel]) ) {
  os_options = join( sort( keys(aix_ntp_vulns) ), sep:' / ' );
  audit(AUDIT_OS_NOT, os_options, version_report);
}

version_report = version_report + " ML " + ml;
if ( empty_or_null(aix_ntp_vulns[oslevel][ml]) ) {
  ml_options = join( sort( keys(aix_ntp_vulns[oslevel]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "ML " + ml_options, version_report);
}

version_report = version_report + " SP " + sp;
if ( empty_or_null(aix_ntp_vulns[oslevel][ml][sp]) ) {
  sp_options = join( sort( keys(aix_ntp_vulns[oslevel][ml]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "SP " + sp_options, version_report);
}

foreach package ( keys(aix_ntp_vulns[oslevel][ml][sp]) ) {
  package_info = aix_ntp_vulns[oslevel][ml][sp][package];
  minfilesetver = package_info["minfilesetver"];
  maxfilesetver = package_info["maxfilesetver"];
  patch =         package_info["patch"];
  if (aix_check_ifix(release:oslevel, ml:ml, sp:sp, patch:patch, package:package, minfilesetver:minfilesetver, maxfilesetver:maxfilesetver) < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.ntp / bos.net.tcp.ntpd / bos.net.tcp.client");
}
