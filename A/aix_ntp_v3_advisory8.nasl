#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102129);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2016-7427",
    "CVE-2016-7428",
    "CVE-2016-9310",
    "CVE-2016-9311"
  );
  script_bugtraq_id(
    94444,
    94446,
    94447,
    94452
  );
  script_xref(name:"CERT", value:"633847");

  script_name(english:"AIX NTP v3 Advisory : ntp_advisory8.asc (IV92194) (IV91803) (IV92193) (IV91951) (IV92192) (IV92067)");
  script_summary(english:"Checks the version of the ntp packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NTP installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NTP installed on the remote AIX host is affected by
the following vulnerabilities :

  - A denial of service vulnerability exists in the
    broadcast mode replay prevention functionality. An
    unauthenticated, adjacent attacker can exploit this, via
    specially crafted broadcast mode NTP packets
    periodically injected into the broadcast domain, to
    cause ntpd to reject broadcast mode packets from
    legitimate NTP broadcast servers. (CVE-2016-7427)

  - A denial of service vulnerability exists in the
    broadcast mode poll interval functionality. An
    unauthenticated, adjacent attacker can exploit this, via
    specially crafted broadcast mode NTP packets, to cause
    ntpd to reject packets from a legitimate NTP broadcast
    server. (CVE-2016-7428)

  - A flaw exists in the control mode (mode 6) functionality
    when handling specially crafted control mode packets. An
    unauthenticated, adjacent attacker can exploit this to
    set or disable ntpd traps, resulting in the disclosure
    of potentially sensitive information, disabling of
    legitimate monitoring, or DDoS amplification.
    (CVE-2016-9310)

  - A NULL pointer dereference flaw exists in the
    report_event() function within file ntpd/ntp_control.c
    when the trap service handles certain peer events. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted packet, to cause a denial of service
    condition. (CVE-2016-9311)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/ntp_advisory8.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");

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
          "patch":"(IV92194m9a|IV96305m9a)"
        }
      }
    }
  },
  "6.1": {
    "09": {
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV91803m6a)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV91803m6a|IV96306m9a)"
        }
      },
      "08": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV91803m6a|IV96306m9a)"
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
          "patch":"(IV92193m5a)"
        }
      },
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.46",
          "patch":"(IV92193m5a)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.47",
          "patch":"(IV92193m5a|IV96307m9a)"
        }
      },
      "08": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.48",
          "patch":"(IV92193m5a|IV96307m9a)"
        }
      }
    },
    "04": {
      "01": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV91951m3a)"
        }
      },
      "02": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV91951m3a|IV96308m4a)"
        }
      },
      "03": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV91951m3a|IV96308m4a)"
        }
      }
    }
  },
  "7.2": {
   "00": {
      "00": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92192m2a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92192m2a)"
        }
      },
      "01": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92192m2a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92192m2a)"
        }
      },
      "02": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92192m2a|IV96309m4a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92192m2a|IV96309m4a)"
        }
      }
    },
   "01": {
      "00": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.0",
          "patch":"(IV92067s1a|IV96310m2a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.0",
          "patch":"(IV92067s1a|IV96310m2a)"
        }
      },
      "01": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.0",
          "patch":"(IV92067s1a|IV96310m2a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.0",
          "patch":"(IV92067s1a|IV96310m2a)"
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
