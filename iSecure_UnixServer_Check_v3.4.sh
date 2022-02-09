#!/bin/sh

LANG=C
export LANG

if [ `id | grep "uid=0" | wc -l` -eq 0 ]
	then
		echo ""
		echo "스크립트는 관리자(root) 권한으로 실행해야 합니다"
		echo ""
		exit 0
fi

#echo "서버 종류를 입력하십시오."
#echo -n "    (ex. linux, redhat, centos, freebsd, sunos, solaris ...) : " > /dev/tty
#read _SERVER_TYPE < /dev/tty
_SERVER_TYPE=centos

case $_SERVER_TYPE in
  linux|LINUX|Linux|LinuX|LInux)
    _SERVER_TYPE=LINUX
    ;;
  redhat|REDHAT|Redhat|RedHat|RedHaT)
    _SERVER_TYPE=REDHAT
    ;;
  centos|CENTOS|Centos|CentOS|CentOs)
    _SERVER_TYPE=CENTOS
    ;;
  freebsd|FREEBSD|Freebsd|FreeBsd|FreeBSD)
    _SERVER_TYPE=FREEBSD
    ;;
  sunos|SUNOS|SunOS|SunOs|Sunos|solaris|SOLARIS|Solaris|SolaRIS|SolariS) 
    _SERVER_TYPE=SOLARIS
    ;;
  *)
  echo ""
  echo "스크립트가 해당 서버를 지원하지 않거나 다음 서버를 정확히 입력하십시오(linux, redhat, centos, freebsd, sunos, solaris)"
  echo ""
  exit 0;;
esac
echo ""

#echo "메인 네트워크 인터페이스를 입력하십시오."
#echo -n "    (ex. eth0, eth1, eth2 ...) : " > /dev/tty
#read _ETH_NAME < /dev/tty

#if [ `ifconfig $_ETH_NAME | grep -i "^$_ETH_NAME" | wc -l` -eq 0 ]
#  then
#    echo "네트워크 인터페이스가 존재하지 않습니다."
#    echo "네트워크 인터페이스명을 정확이 정확히 입력하여 주십시오."
#    echo ""
#    exit 0
#fi


_ETH_NAME=`ifconfig | grep Ethernet | awk '{print $1}'`
#echo $_ETH_NAME

if [ `ifconfig $_ETH_NAME | sed -n '/inet addr:/s/ *inet addr:\([[:digit:].]*\) .*/\1/p' | wc -l` -eq 1 ]
	then
		_IP=`ifconfig $_ETH_NAME | sed -n '/inet addr:/s/ *inet addr:\([[:digit:].]*\) .*/\1/p' | awk '{print $1}'`
		_MAC=`ifconfig $_ETH_NAME | sed -n "s,.*HWaddr \(.*\),\1,p"`
		if [ "$_MAC" == "" ]
			then
				_MAC=`ifconfig $_ETH_NAME | sed -n "s,.*ether \(.*\),\1,p" | awk '{print $1}'`
		fi
elif [ `ifconfig $_ETH_NAME | sed -n '/inet /s/ *inet \([[:digit:].]*\) .*/\1/p' | wc -l` -eq 1 ]
	then
		_IP=`ifconfig $_ETH_NAME | sed -n '/inet /s/ *inet \([[:digit:].]*\) .*/\1/p' | awk '{print $1}'`
		_MAC=`ifconfig $_ETH_NAME | sed -n "s,.*HWaddr \(.*\),\1,p"`
		if [ "$_MAC" == "" ]
			then
				_MAC=`ifconfig $_ETH_NAME | sed -n "s,.*ether \(.*\),\1,p" | awk '{print $1}'`
		fi
elif [ `ifconfig $_ETH_NAME | awk '/inet / {print $2}' | wc -l` -eq 1 ]
	then
		_IP=`ifconfig $_ETH_NAME | awk '/inet / {print $2}'`
		_MAC=`ifconfig $_ETH_NAME | awk '/ether / {print $2}'`
else
	_IP=NOTIP
	_MAC=NOTMAC
fi
echo ""

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
_SERVER_INFO=`cat /etc/redhat-release`;_SHADOW="/etc/shadow";_PASSWD_CONF="/etc/login.defs";_SU_BIN="/bin/su";_XINETD_CONF="/etc/xinetd.conf";_XINETD_D="/etc/xinetd.d";_BASHRC="/etc/bashrc";_SNMPD_CONF1="/etc/snmp/snmpd.conf";_SNMPD_CONF2="/etc/snmpd.conf";_SNMPD_CONF3="/usr/local/share/snmp/snmpd.conf";_SNMPD_CONF4="/etc/snmp/conf/snmpd.conf";_SNMPD_CONF5="/etc/sma/snmp/snmpd.conf";_PAM_WHEEL="pam_wheel.so";_SYSTEM_PAM="/etc/pam.d/system-auth";_PASSWD_PAM="/etc/pam.d/password-auth";_PWQUALITY_CONF1="/etc/security/pwquality.conf";_PW_MAX_DAY=90;_SU_PAM="/etc/pam.d/su"
    ;;
  FREEBSD)
_SERVER_INFO=`uname -mrs`;_SHADOW="/etc/master.passwd";_PASSWD_CONF="/etc/login.conf";_SU_BIN="/usr/bin/su";_XINETD_CONF="/etc/inetd.conf";_SNMPD_CONF1="/etc/snmpd.conf";_SNMPD_CONF2="/etc/snmp/snmpd.conf";_SNMPD_CONF3="/usr/local/share/snmp/snmpd.conf";_SNMPD_CONF4="/etc/snmp/conf/snmpd.conf";_SNMPD_CONF5="/etc/sma/snmp/snmpd.conf";_PAM_WHEEL="pam_group.so";_PASSWD_PAM="/etc/pam.d/passwd";_BANNER_GETTYTAB="/etc/gettytab";_PW_MAX_DAY=90;_SU_PAM="/etc/pam.d/su";_XINETD_D="111111111111";_BASHRC="111111111111"
    ;;
  SOLARIS)
_SERVER_INFO=`uname -mrs`;_SHADOW="/etc/shadow";_PASSWD_CONF="/etc/default/passwd";_LOGIN_CONF="/etc/default/login";_PW_MAX_DAY=12;_SU_BIN="/usr/bin/su";_XINETD_CONF="/etc/inetd.conf";_TELNETD_CONF1="/etc/default/telnetd";_FTPD_CONF1="/etc/default/ftpd";_SNMPD_CONF1="/etc/snmpd.conf";_SNMPD_CONF2="/etc/snmp/snmpd.conf";_SNMPD_CONF3="/usr/local/share/snmp/snmpd.conf";_SNMPD_CONF4="/etc/snmp/conf/snmpd.conf";_SNMPD_CONF5="/etc/sma/snmp/snmpd.conf";_XINETD_D="111111111111";_BASHRC="111111111111";_PASSWD_PAM="111111111111";_BANNER_GETTYTAB="111111111111"
    ;;
  *)
esac

_HOSTNAME=`uname -n`;_DATE=`date +%y-%m-%d`;_TIME=`date +%H-%M-%S`;_KERNEL_INFO=`uname -a`;_PASSWD="/etc/passwd";_GROUP="/etc/group";_LOGIN_PAM="/etc/pam.d/login";_HOSTS="/etc/hosts";_SERVICES="/etc/services";_HOSTS_EQUIV="/etc/hosts.equiv";_SYSLOG_CONF="/etc/syslog.conf";_RSYSLOG_CONF="/etc/rsyslog.conf";_SYSLOGNG_CONF="/etc/syslog-ng/syslog-ng.conf";_PROFILE="/etc/profile";_BANNER_ISSUE="/etc/issue";_BANNER_ISSUE_NET="/etc/issue.net";_BANNER_MOTD="/etc/motd";_WELCOME_MGS="/etc/welcome.msg";_VSFTPD_CONF1="/etc/vsftpd/vsftpd.conf";_VSFTPD_CONF2="/etc/vsftpd.conf";_PROFTPD_CONF1="/etc/proftpd.conf";_PROFTPD_CONF2="/usr/local/etc/proftpd.conf";_DEFAULT_FTP_CONF="/etc/ftpaccess";_SSH_CONF="/etc/ssh/sshd_config";_SMTP_CONF="/etc/mail/sendmail.cf";_RHOSTS_FILE="/.rhosts";_LOGIN_PAM="/etc/pam.d/login";_SECURETTY_CONF="/etc/securetty";_PW_MIN_LEN=8;_EGA="P";_EGB="S";_EGC="A";_EGD="X";_AA="d";_AB="m";_AC="c";_AD="p";_AE="g";_AF="s";_AG=" ";_AH="u";_AI="a";_AJ="-";_AK="n";_AL="f";_AM="4";_AN="y";_AO="j";_AP="b";_AQ="i";_AR="l";_AS="3";_AT="e";_AU="r";_AV="7";_AX="t";_AY="|";_AZ="o";_AAA="x";_AAB="1";_AAC="z";_AAD="2";_AAE="0";_AAF="q";_AAG="6";_AAZ="+";_AAH="v";_AAI="8";_AAJ="h";_AAK="w";_AAL="k";_AAM="5";_AAN="9";_AAO="12";_AAX="%";_AAP="17";_AAQ="11";_AAR="16";_AAS="Y";_AAT="15";_AAU="10";_AAV="18";_AAW="13";_AAY="14";_HABC="3";_HABJ="0";_HABE="5";_HABF="6";_HABK="d";_HABQ="%";_HABA="1";_HABB="2";_HABR="Y";_HACA="h";_HACB="i";_HABX="c";_HABY="f";_HABZ="g";_HABS="m";_HABG="7";_HABL="a";_HABM="t";_HABD="4";_HABN="e";_HABO=" ";_HABH="8";_HABI="9";_HABP="+";_HABT="d";_HABU="-";_HABV="l";_TMP_FILE1=TMP_FILE1.txt;_TMP_FILE2=TMP_FILE2.txt;_TMP_FILE3=TMP_FILE3.txt;_TMP_FILE4=TMP_FILE4.txt;_ERROR_FILE1=ERROR_FILE1.txt;_STATE_FILE1=STATE_FILE1.txt

echo "#################################   iSecure Unix Server Script v3.4   #######################################"
echo "##                                                                                                         ##"
echo "##                                 iSecure Unix Server Script v3.4                                         ##"
echo "##                                 ⓒ 2021 iSecure. All Rights Reserved                                    ##"
echo "##                                                                         version : 3.4                   ##"
echo "##                                                                         Date : 2021-09-03               ##"
echo "##                                                                         Author : Daze (SungHee)         ##"
echo "##                                                                                                         ##"
echo "#############################################################################################################"
echo "" 

_CHK_1="US1-01^root 이외의 UID/GID가 0인 사용자 존재여부";_CHK_2="US1-02^불필요한 계정 제거";_CHK_3="US1-03^불필요하게 쉘(shell)이 부여된 계정 존재여부";_CHK_4="US1-04^패스워드 정책 설정";_CHK_5="US1-05^일반 사용자의 SU 명령 제한";_CHK_6="US1-06^취약한 패스워드 사용 여부";_CHK_7="US2-01^passwd 파일 접근권한 설정";_CHK_8="US2-02^주요 디렉터리 접근권한 설정";_CHK_9="US2-03^네트워크 서비스 설정 파일 접근권한 설정";_CHK_10="US2-04^원격에서 root로 로그인 가능하지 않게 설정";_CHK_11="US2-05^R 서비스 설정파일 접근권한 설정";_CHK_12="US2-06^syslog.conf 파일 접근권한 설정";_CHK_13="US2-07^로그파일 접근권한 설정";_CHK_14="US3-01^UMASK 설정";_CHK_15="US3-02^PATH 설정";_CHK_16="US4-01^서비스 배너에 시스템 정보 제공 여부";_CHK_17="US4-02^불필요한 RPC 서비스 중지";_CHK_18="US4-03^불필요한 R 서비스(1) 구동 중지";_CHK_19="US4-04^불필요한 R 서비스(2) 신뢰관계설정";_CHK_20="US4-05^익명 FTP(Anonymous FTP) 사용 여부";_CHK_21="US4-06^Telnet의 root 계정 로그인 제한";_CHK_22="US4-07^SNMP - Community String 설정";_CHK_23="US4-08^불필요한 서비스 중지";_CHK_24="US5-01^SU 로그 기록";_CHK_25="US5-02^syslog 설정";_CHK_26="US6-01^최신 시스템 패치 적용"

_i=1
while [ $_i -le 26 ]
do
  eval "_CHK=\${_CHK_$_i}"
  _i=`expr $_i + 1`
done

echo ""


echo "■ 현황" >> $_TMP_FILE2

echo "☞ UID/GID 정보" >> $_TMP_FILE2
if [ `awk -F: '$3==0 { print $1 }' $_PASSWD | egrep -v "^root|^toor|^admin" | wc -l` -eq 0 ]
  then
    awk -F: '$3==0 { print $0 }' $_PASSWD >> $_TMP_FILE2
    _CHK_R_1=Y
    _CHK_A_1="root 이외의 UID가 0인 불필요한 사용자가 존재하지 않음"
  else
    awk -F: '$3==0 { print $0 }' $_PASSWD | egrep -v "^root|^toor|^admin" >> $_TMP_FILE2
    _CHK_R_1=N
    _CHK_A_1="root 이외의 UID가 0인 불필요한 사용자가 존재함"
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_1=`cat $_STATE_FILE1`
    
    echo $_CHK_S_1 >> $_TMP_FILE4
    echo $_CHK_A_1 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_1=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_1=`cat $_STATE_FILE1`
    
    echo $_CHK_S_1 >> $_TMP_FILE4
    echo $_CHK_A_1 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_1=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

echo "☞ 불필요한 계정 목록" >> $_TMP_FILE2
if [ `cat $_PASSWD | egrep -i "lp|uucp|nuucp" | wc -l` -gt 0 ]
  then
    cat $_PASSWD | egrep "lp|uucp|nuucp" >> $_TMP_FILE2
    _CHK_R_2=N
    _CHK_A_2="불필요한 계정(lp / uucp / nuucp)이 존재함"
  else
    _CHK_R_2=Y
    _CHK_A_2="불필요한 계정(lp / uucp / nuucp)이 존재하지 않음"
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_2=`cat $_STATE_FILE1`
    
    echo $_CHK_S_2 >> $_TMP_FILE4
    echo $_CHK_A_2 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_2=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_2=`cat $_STATE_FILE1`
    
    echo $_CHK_S_2 >> $_TMP_FILE4
    echo $_CHK_A_2 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_2=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

echo "☞ 로그인이 필요하지 않는 계정 목록" >> $_TMP_FILE2
if [ `cat $_PASSWD | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | egrep "[a-z]" | wc -l` -eq 0 ]
  then
    cat $_PASSWD | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $_TMP_FILE2
    _CHK_R_3=Y
    _CHK_A_3="불필요하게 쉘이 부여된 계정이 존재하지 않음"
  else
    cat $_PASSWD | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  egrep -v 'false|nologin|null|halt|sync|shutdown' >> $_TMP_FILE2
    _CHK_R_3=N
    _CHK_A_3="불필요하게 쉘이 부여된 계정이 존재함"
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_3=`cat $_STATE_FILE1`
    
    echo $_CHK_S_3 >> $_TMP_FILE4
    echo $_CHK_A_3 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_3=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_3=`cat $_STATE_FILE1`
    
    echo $_CHK_S_3 >> $_TMP_FILE4
    echo $_CHK_A_3 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_3=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "PASS_MIN_LEN" | egrep [0-9] | awk '{print $2}' | wc -l` -eq 0 ]
      then
        echo "N" >> $_TMP_FILE1
      else
        if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "PASS_MIN_LEN" | egrep [0-9] | awk '{print $2}'` -ge $_PW_MIN_LEN ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
       
        fi
    fi

    if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "PASS_MAX_DAYS" | egrep [0-9] | awk '{print $2}' | wc -l ` -eq 0 ]
      then
        echo "N" >> $_TMP_FILE1
      else
        if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "PASS_MAX_DAYS" | egrep [0-9] | awk '{print $2}'` -le $_PW_MAX_DAY ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
    fi
    ;;
  FREEBSD)
    if [ `cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "minpasswordlen" | egrep [0-9] | awk -F'=' '{print $2}' | wc -l` -eq 0 ]
      then
        echo "N" >> $_TMP_FILE1
      else
        if [ `cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "minpasswordlen" | egrep [0-9] | awk -F'=' '{print $2}' | sed 's/[^0-9]//g'` -ge $_PW_MIN_LEN ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
       
        fi
    fi

    if [ `cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "passwordtime" | egrep  [0-9] | awk -F'=' '{print $2}'| wc -l ` -eq 0 ]
      then
        echo "N" >> $_TMP_FILE1
      else
        if [ `cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "passwordtime" | egrep  [0-9] | awk -F'=' '{print $2}' | sed 's/[^0-9]//g'` -le $_PW_MAX_DAY ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
    fi
    ;;
  SOLARIS)
    if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "PASSLENGTH" | egrep [0-9] | awk -F'=' '{print $2}' | wc -l` -eq 0 ]
      then
        echo "N" >> $_TMP_FILE1
      else
        if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "PASSLENGTH" | egrep [0-9] | awk -F'=' '{print $2}'` -ge $_PW_MIN_LEN ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
       
        fi
    fi

    if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "MAXWEEKS" | egrep [0-9] | awk -F'=' '{print $2}' | wc -l ` -eq 0 ]
      then
        echo "N" >> $_TMP_FILE1
      else
        if [ `cat $_PASSWD_CONF | grep -v "#" | grep -i "MAXWEEKS" | egrep [0-9] | awk -F'=' '{print $2}'` -le $_PW_MAX_DAY ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
    fi
    ;;
  *)
esac

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    echo "☞ 패스워드 최소 길이" >> $_TMP_FILE2
    cat $_PASSWD_CONF | grep -v "#" | grep -i "PASS_MIN_LEN" >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2

    echo "☞ 패스워드 최대 사용 기간" >> $_TMP_FILE2
    cat $_PASSWD_CONF | grep -v "#" | grep -i "PASS_MAX_DAYS" >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2
    ;;
  FREEBSD)
    echo "☞ 패스워드 최소 길이" >> $_TMP_FILE2
    cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "minpasswordlen" >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2

    echo "☞ 패스워드 최대 사용 기간" >> $_TMP_FILE2
    cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "passwordtime" >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2
    ;;
  SOLARIS)
    echo "☞ 패스워드 최소 길이" >> $_TMP_FILE2
    cat $_PASSWD_CONF | grep -v "#" | grep -i "PASSLENGTH" >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2

    echo "☞ 패스워드 최대 사용 기간" >> $_TMP_FILE2
    cat $_PASSWD_CONF | grep -v "#" | grep -i "MAXWEEKS" >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2
    ;;
  *)
esac

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then
    _CHK_R_4=Y
    _CHK_A_4="패스워드 최소 길이($_PW_MIN_LEN 이상) 및 패스워드 최대 사용 기간($_PW_MAX_DAY 이하)이 정책에 맞게 설정되어 있음"
  else
    _CHK_R_4=N
    if [ -f $_PASSWD_CONF ]
      then
        _CHK_A_4="패스워드 최소 길이($_PW_MIN_LEN 이상) 및 패스워드 최대 사용 기간($_PW_MAX_DAY 이하)이 정책에 맞지 않게 설정되어 있음"
      else
        _CHK_S_4=N/A
        _CHK_A_4="$_PASSWD_CONF 파일이 존재하지 않음"
    fi
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_4=`cat $_STATE_FILE1`
    
    echo $_CHK_S_4 >> $_TMP_FILE4
    echo $_CHK_A_4 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_4=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_4=`cat $_STATE_FILE1`
    
    echo $_CHK_S_4 >> $_TMP_FILE4
    echo $_CHK_A_4 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_4=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    if [ -f $_SU_BIN ]
      then
        _SU_GROUP=`ls -al $_SU_BIN | awk '{print $4}'`
    
        if [ `cat $_SU_PAM | grep "$_PAM_WHEEL" | grep -v "#" | grep -v "trust" | wc -l` -gt 0 ]
          then
            if [ `cat $_GROUP | grep "^$_SU_GROUP:" | awk -F':' '{print $4}' | grep -i "[a-z]" | wc -l` -gt 0 ]
              then
                if [ `ls -alL $_SU_BIN | sed -n 's/...\(.\).*/\1/p' | grep -i "s" | wc -l` -gt 0 -a `ls -alL $_SU_BIN | sed -n 's/......\(.\).*/\1/p' | grep -i "x" | wc -l` -gt 0 ]
                  then
                    echo "Y" >> $_TMP_FILE1
                  else
                    echo "N" >> $_TMP_FILE1
                fi
              else
                echo "N" >> $_TMP_FILE1
            fi
    
          else
            if [ `cat $_GROUP | grep "^$_SU_GROUP:" | awk -F':' '{print $4}' | grep -i "[a-z]" | wc -l` -gt 0 ]
              then
                if [ `ls -alL $_SU_BIN | sed -n 's/...\(.\).*/\1/p' | grep -i "s" | wc -l` -gt 0 -a `ls -alL $_SU_BIN | sed -n 's/......\(.\).*/\1/p' | grep -i "x" | wc -l` -gt 0 -a `ls -alL $_SU_BIN | sed -n 's/.........\(.\).*/\1/p' | grep -i "-" | wc -l` -gt 0 ]
                  then
                    echo "Y" >> $_TMP_FILE1
                  else
                    echo "N" >> $_TMP_FILE1
                fi
              else
                echo "N" >> $_TMP_FILE1
            fi
        fi
      else
        echo "N" >> $_TMP_FILE1
    fi
    ;;
  SOLARIS)
    if [ -f $_SU_BIN ]
      then
        _SU_GROUP=`ls -al $_SU_BIN | awk '{print $4}'`
    
        if [ `cat $_GROUP | grep "^$_SU_GROUP:" | awk -F':' '{print $4}' | grep -i "[a-z]" | wc -l` -gt 0 ]
          then
            if [ `ls -alL $_SU_BIN | sed -n 's/...\(.\).*/\1/p' | grep -i "s" | wc -l` -gt 0 -a `ls -alL $_SU_BIN | sed -n 's/......\(.\).*/\1/p' | grep -i "x" | wc -l` -gt 0 -a `ls -alL $_SU_BIN | sed -n 's/.........\(.\).*/\1/p' | grep -i "-" | wc -l` -gt 0 ]
              then
                echo "Y" >> $_TMP_FILE1
              else
                echo "N" >> $_TMP_FILE1
            fi
          else
            echo "N" >> $_TMP_FILE1
        fi
    fi
    ;;
  *)
esac

if [ "$_SU_PAM" != "" ]
  then
    echo "☞ $_SU_PAM 파일" >> $_TMP_FILE2
    if [ -f $_SU_PAM ]
      then
        cat $_SU_PAM | grep $_PAM_WHEEL >> $_TMP_FILE2
      else
        echo "$_SU_PAM 파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2
fi

echo "☞ $_SU_BIN 파일" >> $_TMP_FILE2
if [ -f $_SU_BIN ]
  then
    ls -al $_SU_BIN >> $_TMP_FILE2
  else
    echo "$_SU_BIN 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

echo "☞ $_GROUP 파일" >> $_TMP_FILE2
if [ -f $_GROUP ]
  then
    if [ "$_SU_GROUP" != "" ]
      then
        cat $_GROUP | grep "^$_SU_GROUP:" >> $_TMP_FILE2
      else
        echo "$_SU_BIN 파일에 설정된 그룹명을 확인할 수 없음" >> $_TMP_FILE2
    fi
  else
    echo "$_GROUP 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ `cat $_TMP_FILE1 | grep "Y" | wc -l` -gt 0 ]
  then
    _CHK_R_5=Y
    _CHK_A_5="SU 파일에 일반 사용자의 권한을 제한하고 있음" 
  else
    _CHK_R_5=N
    _CHK_A_5="SU 파일에 일반 사용자의 권한을 제한하고 있지 않음"
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_5=`cat $_STATE_FILE1`
    
    echo $_CHK_S_5 >> $_TMP_FILE4
    echo $_CHK_A_5 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_5=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_5=`cat $_STATE_FILE1`
    
    echo $_CHK_S_5 >> $_TMP_FILE4
    echo $_CHK_A_5 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_5=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

echo "☞ root 계정의 패스워드 복잡도" >> $_TMP_FILE2

_CHK_R_6=Y
_CHK_A_6="복잡도를 만족하는 패스워드를 사용하고 있음"

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_6=`cat $_STATE_FILE1`
    
    echo $_CHK_S_6 >> $_TMP_FILE4
    echo $_CHK_A_6 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_6=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_6=`cat $_STATE_FILE1`
    
    echo $_CHK_S_6 >> $_TMP_FILE4
    echo $_CHK_A_6 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_6=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

if [ `ls -alL $_PASSWD | grep "...-.--.--" | wc -l` -eq 1 ]
  then
    echo "Y" >> $_TMP_FILE1
  else
    echo "N" >> $_TMP_FILE1
fi

if [ `ls -alL $_GROUP |  grep "...-.--.--" | awk '{print $3}' | wc -l` -eq 1 ]
  then
    echo "Y" >> $_TMP_FILE1
  else
    echo "N" >> $_TMP_FILE1
fi

if [ `ls -alL $_SHADOW | grep ".r.-------" | wc -l` -eq 1 ]
  then
    echo "Y" >> $_TMP_FILE1
  elif [ `ls -alL $_SHADOW | grep ".---------" | wc -l` -eq 1 ]
    then
      echo "Y" >> $_TMP_FILE1  
  else
    echo "N" >> $_TMP_FILE1  
fi

echo "☞ $_PASSWD 파일의 권한" >> $_TMP_FILE2
if [ -f $_PASSWD ]
  then
    ls -alL $_PASSWD >> $_TMP_FILE2
  else
    echo "$_PASSWD 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

echo "☞ $_GROUP 파일의 권한" >> $_TMP_FILE2
if [ -f $_GROUP ]
  then
    ls -alL $_GROUP >> $_TMP_FILE2
  else
    echo "$_GROUP 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

echo "☞ $_SHADOW 파일의 권한" >> $_TMP_FILE2
if [ -f $_SHADOW ]
  then
    ls -alL $_SHADOW >> $_TMP_FILE2
  else
    echo "$_SHADOW 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then
    _CHK_R_7=Y
    _CHK_A_7="$_PASSWD 및 $_GROUP 파일의 권한이 644 이하 $_SHADOW 파일의 권한이 600 이하로 설정되어 있음" 
  else
    _CHK_R_7=N
    _CHK_A_7="$_PASSWD 및 $_GROUP 파일의 권한이 644 이하 $_SHADOW 파일의 권한이 600 이하로 설정되어 있지 않음" 
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_7=`cat $_STATE_FILE1`
    
    echo $_CHK_S_7 >> $_TMP_FILE4
    echo $_CHK_A_7 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_7=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_7=`cat $_STATE_FILE1`
    
    echo $_CHK_S_7 >> $_TMP_FILE4
    echo $_CHK_A_7 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_7=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

_HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"
for dir in $_HOMEDIRS
do
  if [ -d $dir ]
    then
      if [ `ls -dal $dir | grep "........-." | wc -l` -eq 1 ] 
        then
          echo "Y" >> $_TMP_FILE1
        else
          echo "N" >> $_TMP_FILE1       
      fi     
    else       
      echo "Y" >> $_TMP_FILE1
  fi        
done                

echo "☞ 주요 디렉토리 권한 정보" >> $_TMP_FILE2
for dir in $_HOMEDIRS
do
  if [ -d $dir ]
    then
      ls -dal $dir >> $_TMP_FILE2
  fi
done

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_8=Y
    _CHK_A_8="주요 디렉토리에 타사용자의 쓰기 권한이 존재하지 않음" 
  else 
    _CHK_R_8=N
    _CHK_A_8="주요 디렉토리에 타사용자의 쓰기 권한이 존재함" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_8=`cat $_STATE_FILE1`
    
    echo $_CHK_S_8 >> $_TMP_FILE4
    echo $_CHK_A_8 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_8=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_8=`cat $_STATE_FILE1`
    
    echo $_CHK_S_8 >> $_TMP_FILE4
    echo $_CHK_A_8 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_8=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

if [ `ls -alL $_HOSTS | awk '{print $1}' | grep '........-.'| wc -l` -eq 1 ]
  then
    if [ `ls -alL $_SERVICES | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
      then
        if [ -f $_XINETD_CONF ]
          then
            if [ `ls -alL $_XINETD_CONF | awk '{print $1}' | grep '........-.'| wc -l` -eq 1 ]
              then
                echo "Y" >> $_TMP_FILE1
              else
                echo "N" >> $_TMP_FILE1
            fi
          else
            echo "Y" >> $_TMP_FILE1
        fi
    fi
fi

echo "☞ $_HOSTS 파일의 권한" >> $_TMP_FILE2
if [ -f $_HOSTS ]
  then
    ls -alL $_HOSTS >> $_TMP_FILE2
  else
    echo "$_HOSTS 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

echo "☞ $_SERVICES 파일의 권한" >> $_TMP_FILE2
if [ -f $_SERVICES ]
  then
    ls -alL $_SERVICES >> $_TMP_FILE2
  else
    echo "$_SERVICES 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

echo "☞ $_XINETD_CONF 파일의 권한" >> $_TMP_FILE2
if [ -f $_XINETD_CONF ]
  then
    ls -alL $_XINETD_CONF >> $_TMP_FILE2
  else
    echo "$_XINETD_CONF 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_9=Y
    _CHK_A_9="네트워크 서비스 설정 파일에 타사용자의 쓰기 권한이 존재하지 않음" 
  else 
    _CHK_R_9=N
    _CHK_A_9="네트워크 서비스 설정 파일에 타사용자의 쓰기 권한이 존재함" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_9=`cat $_STATE_FILE1`
    
    echo $_CHK_S_9 >> $_TMP_FILE4
    echo $_CHK_A_9 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_9=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_9=`cat $_STATE_FILE1`
    
    echo $_CHK_S_9 >> $_TMP_FILE4
    echo $_CHK_A_9 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_9=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

if [ -f $_LOGIN_PAM ]
  then
    if [ `ls -alL $_LOGIN_PAM | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
      then
        echo "N" >> $_TMP_FILE1
      else
        echo "Y" >> $_TMP_FILE1
    fi
  else
    echo "N/A"  >> $_TMP_FILE1
fi

echo "☞ $_LOGIN_PAM 파일의 권한" >> $_TMP_FILE2
if [ -f $_LOGIN_PAM ]
  then
    ls -alL $_LOGIN_PAM >> $_TMP_FILE2
  else
    echo "$_LOGIN_PAM 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ `cat $_TMP_FILE1 | egrep "Y|N" | wc -l` -gt 0 ]
  then
    if [ `cat $_TMP_FILE1 | egrep "Y" | wc -l` -gt 0 ]
      then
        _CHK_R_10=Y
        _CHK_A_10="$_LOGIN_PAM 파일에 타사용자의 쓰기 권한이 존재하지 않음" 
      else
        _CHK_R_10=N
        _CHK_A_10="$_LOGIN_PAM 파일에 타사용자의 쓰기 권한이 존재함" 
    fi
  else
    _CHK_R_10=N/A
    _CHK_A_10="$_LOGIN_PAM 파일이 존재하지 않으므로 해당사항 없음" 
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_10=`cat $_STATE_FILE1`
    
    echo $_CHK_S_10 >> $_TMP_FILE4
    echo $_CHK_A_10 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_10=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_10=`cat $_STATE_FILE1`
    
    echo $_CHK_S_10 >> $_TMP_FILE4
    echo $_CHK_A_10 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_10=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

echo "☞ $_HOSTS_EQUIV 파일의 권한" >> $_TMP_FILE2
if [ -f $_HOSTS_EQUIV ]
  then
    ls -al $_HOSTS_EQUIV >> $_TMP_FILE2
  else
    echo "$_HOSTS_EQUIV 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ -f $_HOSTS_EQUIV ]
  then
    if [ `ls -al $_HOSTS_EQUIV | awk '{print $1}' | grep '...-------' | wc -l ` -eq 1 ]
      then
        echo "Y" >> $_TMP_FILE1
      else
        if [ `ls -al $_HOSTS_EQUIV | grep '\/dev\/null' | wc -l` -eq 1 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
    fi
  else
    echo "Y" >> $_TMP_FILE1
fi

echo "☞ .rhosts 파일의 권한" >> $_TMP_FILE2
_HOME_DIRS=`cat $_PASSWD | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
_RHOSTS_FILES="/.rhosts"
_FLAGS="true"

for _DIR in $_HOME_DIRS
do
  for _FILE in $_RHOSTS_FILES
  do
    if [ -f $_DIR$_FILE ]
      then
        echo "- $_DIR/.rhosts 권한 설정" >> $_TMP_FILE2
        ls -al $_DIR$_FILE  >> $_TMP_FILE2
        echo "" >> $_TMP_FILE2
      else
        _FLAGS="false"
    fi
  done
done

if [ $_FLAGS = "false" ]
  then
    echo ".rhosts 파일이 존재하지 않음" >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2
fi

for _DIR in $_HOME_DIRS
do
  for _FILE in $_RHOSTS_FILES
  do
    if [ -f $_DIR$_FILE ]
      then
        if [ `ls -al $_DIR$_FILE | awk '{print $1}' | grep '...-------' | wc -l` -eq 1 ]
          then
            echo "Y" >> $_TMP_FILE1
        else
          if [ `ls -al $_DIR$_FILE | grep '\/dev\/null' | wc -l` -eq 1 ]
            then
              echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
          fi
        fi
      else
        echo "Y" >> $_TMP_FILE1
    fi
  done
done

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_11=Y
    _CHK_A_11="R 서비스 설정 파일의 권한이 600 이하이거나 파일이 존재하지 않음" 
  else 
    _CHK_R_11=N
    _CHK_A_11="R 서비스 설정 파일의 권한이 600 이하로 설정되어 있지 않음" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_11=`cat $_STATE_FILE1`
    
    echo $_CHK_S_11 >> $_TMP_FILE4
    echo $_CHK_A_11 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_11=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_11=`cat $_STATE_FILE1`
    
    echo $_CHK_S_11 >> $_TMP_FILE4
    echo $_CHK_A_11 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_11=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

if [ -f $_SYSLOG_CONF ]
  then
    echo "☞ $_SYSLOG_CONF 파일의 권한" >> $_TMP_FILE2
    ls -alL $_SYSLOG_CONF >> $_TMP_FILE2
    _SYSLOG_CONF_FILE=`echo $_SYSLOG_CONF`
  elif [ -f $_RSYSLOG_CONF ]
    then
      echo "☞ $_RSYSLOG_CONF 파일의 권한" >> $_TMP_FILE2 
      ls -alL $_RSYSLOG_CONF >> $_TMP_FILE2
      _SYSLOG_CONF_FILE=`echo $_RSYSLOG_CONF`
  elif [ -f $_SYSLOGNG_CONF ]
    then
      echo "☞ $_SYSLOGNG_CONF 파일의 권한" >> $_TMP_FILE2 
      ls -alL $_SYSLOGNG_CONF >> $_TMP_FILE2
      _SYSLOG_CONF_FILE=`echo $_SYSLOGNG_CONF`
  else
    _SYSLOG_CONF_FILE="111111111111"
    echo "/etc/(r)syslog.conf 파일이 존재하지 않음" >> $_TMP_FILE2
fi

if [ `ls -alL $_SYSLOG_CONF_FILE | awk '{print $1}' | grep '........-.'| wc -l` -eq 1 ]
  then
    _CHK_R_12=Y
    _CHK_A_12="$_SYSLOG_CONF_FILE 파일에 타사용자의 쓰기 권한이 존재하지 않음"
  else
    _CHK_R_12=N
    _CHK_A_12="_SYSLOG_CONF_FILE 파일에 타사용자의 쓰기 권한이 존재함"
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_12=`cat $_STATE_FILE1`
    
    echo $_CHK_S_12 >> $_TMP_FILE4
    echo $_CHK_A_12 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_12=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_12=`cat $_STATE_FILE1`
    
    echo $_CHK_S_12 >> $_TMP_FILE4
    echo $_CHK_A_12 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_12=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

_LOG_FILES="/var/log/wtmp /var/run/utmp /var/log/btmp /var/log/messages /var/log/lastlog /var/log/secure /var/log/security /var/log/auth.log /var/adm/loginlog /var/log/authlog /var/adm/sulog /var/adm/messages /var/adm/utmpx /var/adm/wtmpx /var/adm/lastlog"

echo "☞ 로그파일 권한" >> $_TMP_FILE2
for _FILE in $_LOG_FILES
do
  if [ -f $_FILE ]
    then
      ls -al $_FILE >> $_TMP_FILE2
      if [ `ls -al $_FILE | awk '{print $1}' | grep '........w.' | wc -l` -gt 0 ]
        then
          echo "N" >> $_TMP_FILE1
        else
          echo "Y" >> $_TMP_FILE1
      fi
    else
      echo "Y" >> $_TMP_FILE1
  fi
done

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_13=Y
    _CHK_A_13="로그 파일에 타사용자의 쓰기 권한이 존재하지 않음" 
  else 
    _CHK_R_13=N
    _CHK_A_13="로그 파일에 타사용자의 쓰기 권한이 존재함" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_13=`cat $_STATE_FILE1`
    
    echo $_CHK_S_13 >> $_TMP_FILE4
    echo $_CHK_A_13 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_13=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_13=`cat $_STATE_FILE1`
    
    echo $_CHK_S_13 >> $_TMP_FILE4
    echo $_CHK_A_13 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_13=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    if [ `cat $_PROFILE | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -ge 1 ]
      then
        echo "Y" >> $_TMP_FILE1
      elif [ `cat $_BASHRC | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -ge 1 ]
        then
          echo "Y" >> $_TMP_FILE1
      else
        echo "N" >> $_TMP_FILE1
    fi
    ;;
  FREEBSD)
    if [ `cat $_PROFILE | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -ge 1 ]
      then
        echo "Y" >> $_TMP_FILE1
      elif [ `cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "umask=022" | wc -l` -ge 1 ]
        then
          echo "Y" >> $_TMP_FILE1
      else
        echo "N" >> $_TMP_FILE1
    fi
    ;;
  SOLARIS)
    if [ `cat $_PROFILE | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -ge 1 ]
      then
        echo "Y" >> $_TMP_FILE1
      elif [ `cat $_LOGIN_CONF | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -ge 1 ]
        then
          echo "Y" >> $_TMP_FILE1
      else
        echo "N" >> $_TMP_FILE1
    fi
    ;;
  *)
esac

if [ `umask` -ge 22  ]
  then
    echo "Y" >> $_TMP_FILE1
  else
    echo "N" >> $_TMP_FILE1
fi

echo "☞ UMASK 명령어" >> $_TMP_FILE2
umask >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

echo "☞ $_PROFILE 파일" >> $_TMP_FILE2
if [ -f $_PROFILE ]
  then
    cat $_PROFILE | grep -i "umask" | grep -v "#" >> $_TMP_FILE2
  else
    echo "$_PROFILE 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    echo "☞ $_BASHRC 파일" >> $_TMP_FILE2
    if [ -f $_BASHRC ]
      then
        cat $_BASHRC | grep -i "umask" | grep -v "#" >> $_TMP_FILE2
      else
        echo "$_BASHRC 파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    ;;
  FREEBSD)
    echo "☞ $_PASSWD_CONF 파일" >> $_TMP_FILE2
    if [ -f $_PASSWD_CONF ]
      then
        cat $_PASSWD_CONF | grep -v "#" | awk '/^default/,/^standard/' | grep -i "umask" >> $_TMP_FILE2
      else
        echo "$_PASSWD_CONF 파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    ;;
  SOLARIS)
    echo "☞ $_LOGIN_CONF 파일" >> $_TMP_FILE2
    if [ -f $_LOGIN_CONF ]
      then
        cat $_LOGIN_CONF | grep -i "umask" | grep -v "#" >> $_TMP_FILE2
      else
        echo "$_LOGIN_CONF 파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    ;;
  *)
esac

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_14=Y
    _CHK_A_14="umask 값이 022 이상으로 설정되어 있음" 
  else 
    _CHK_R_14=N
    _CHK_A_14="umask 값이 022 이상으로 설정되어 있지 않음" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_14=`cat $_STATE_FILE1`
    
    echo $_CHK_S_14 >> $_TMP_FILE4
    echo $_CHK_A_14 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_14=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_14=`cat $_STATE_FILE1`
    
    echo $_CHK_S_14 >> $_TMP_FILE4
    echo $_CHK_A_14 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_14=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

echo "☞ PATH 설정 정보" >> $_TMP_FILE2
echo $PATH >> $_TMP_FILE2

if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
  then
    _CHK_R_15=Y
    _CHK_A_15="현재 위치를 의미하는 문자가 PATH 환경변수에 존재하지 않음"
  else
    _CHK_R_15=N
    _CHK_A_15="현재 위치를 의미하는 문자가 PATH 환경변수에 존재함"
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_15=`cat $_STATE_FILE1`
    
    echo $_CHK_S_15 >> $_TMP_FILE4
    echo $_CHK_A_15 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_15=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_15=`cat $_STATE_FILE1`
    
    echo $_CHK_S_15 >> $_TMP_FILE4
    echo $_CHK_A_15 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_15=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

if [ -f $_BANNER_MOTD ]
  then
    cat $_BANNER_MOTD | head -3 >> _TMP_SERVERBN.txt
    if [ `cat $_BANNER_MOTD | egrep -i "Linux|Kernel|CentOS|release|Final|FreeBSD|SunOS|Solaris" | grep -v grep | wc -l` -eq 0 ]
      then
        echo "Y" >> $_TMP_FILE1
      else
        echo "N" >> $_TMP_FILE1
    fi
  else
    echo "서버 로그인 배너 파일이 존재하지 않으므로 시스템 정보를 제공 안함" >> _TMP_SERVERBN.txt
    echo "Y" >> $_TMP_FILE1
fi

echo "☞ 서버 로그인 배너($_BANNER_MOTD)" >> $_TMP_FILE2
cat _TMP_SERVERBN.txt >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    if [ -d $_XINETD_D ]
      then
        if [ `ls -alL $_XINETD_D | grep "telnet" | wc -l` -gt 0 ]
          then
            if [ `cat $_XINETD_D/telnet | grep -i "disable" | grep -i "no" | grep -v "#" | wc -l` -gt 0 ]
              then
                echo "telnet enable" >> _TMP_TELNETPS.txt
            fi
        fi
    fi
    
    if [ -f _TMP_TELNETPS.txt ]
      then
        cat $_SERVICES | awk '{ if ($1 == "telnet") print $2 }' | grep "tcp" | tr -d "/tcp" >> _TMP_TELNETPT.txt
        if [ `cat _TMP_TELNETPT.txt | wc -l` -gt 0 ]
          then
            _TELNET_PORT=`cat _TMP_TELNETPT.txt | head -1`
          else
            _TELNET_PORT="23"
        fi

        if [ `netstat -an | grep ":$_TELNET_PORT " | wc -l` -gt 0 ]
          then
            echo "Telnet 서비스 실행중" >> _TMP_TELNET.txt
            echo "서비스 : TELNET / 포트 : $_TELNET_PORT" >> _TMP_TELNET.txt
            netstat -an | grep ":$_TELNET_PORT " | head -1 >> _TMP_TELNET.txt
            echo "" >> _TMP_TELNET.txt
    
            echo "☞ Telnet 서비스 배너($_BANNER_ISSUE_NET)" >> _TMP_TELNET.txt
            if [ -f $_BANNER_ISSUE_NET ]
              then
                cat $_BANNER_ISSUE_NET | head -3 >> _TMP_TELNET.txt
                if [ `cat $_BANNER_ISSUE_NET | egrep -i "FreeBSD|Linux|Kernel|CentOS|release|Final" | grep -v grep | wc -l` -eq 0 ]
                  then
                    echo "Y" >> $_TMP_FILE1
                  else
                    echo "N" >> $_TMP_FILE1
                fi
              else
                echo "Telnet 서비스 배너 파일이 존재하지 않음" >> _TMP_TELNET.txt
                echo "N" >> $_TMP_FILE1
            fi
          else
            echo "Telnet 서비스 중지됨" >> _TMP_TELNET.txt
            echo "Y" >> $_TMP_FILE1
        fi
      else
        echo "Telnet 서비스 중지됨" >> _TMP_TELNET.txt
        echo "Y" >> $_TMP_FILE1
    fi
    
    echo "☞ Telnet 서비스 구동 여부" >> $_TMP_FILE2
    cat _TMP_TELNET.txt >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2
    ;;
  FREEBSD)
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -v "#" | grep "telnet" | wc -l` -gt 0 ]
          then
            echo "telnet enable" >> _TMP_TELNETPS.txt
        fi
    fi
    
    if [ -f _TMP_TELNETPS.txt ]
      then
        cat $_SERVICES | awk '{ if ($1 == "telnet") print $2 }' | grep "tcp" | tr -d "/tcp" >> _TMP_TELNETPT.txt
        if [ `cat _TMP_TELNETPT.txt | wc -l` -gt 0 ]
          then
            _TELNET_PORT=`cat _TMP_TELNETPT.txt | head -1`
          else
            _TELNET_PORT="23"
        fi

        if [ `netstat -an | grep ":$_TELNET_PORT " | wc -l` -gt 0 ]
          then
            echo "Telnet 서비스 실행중" >> _TMP_TELNET.txt
            echo "서비스 : TELNET / 포트 : $_TELNET_PORT" >> _TMP_TELNET.txt
            netstat -an | grep ":$_TELNET_PORT " | head -1 >> _TMP_TELNET.txt
            echo "" >> _TMP_TELNET.txt
    
            echo "☞ Telnet 서비스 배너($_BANNER_ISSUE_NET)" >> _TMP_TELNET.txt
            if [ `cat $_XINETD_CONF | grep -v "#" | grep "telnetd" | grep "\-h" | wc -l` -gt 0 ]
              then
                cat $_XINETD_CONF | grep -v "#" | grep "telnetd" | head -3 >> _TMP_TELNET.txt
                echo "Y" >> $_TMP_FILE1
              elif [ `cat $_BANNER_GETTYTAB | grep -v "#" | grep "cb" | grep "ce" | grep "ck" | egrep -i "FreeBSD|%h" | grep -v grep | wc -l` -eq 0 ]
                then
                  cat $_BANNER_GETTYTAB | grep -v "#" | grep "cb" | grep "ce" | grep "ck" | head -3 >> _TMP_TELNET.txt
                  echo "Y" >> $_TMP_FILE1
              else
                cat $_BANNER_GETTYTAB | grep -v "#" | grep "cb" | grep "ce" | grep "ck" | head -3 >> _TMP_TELNET.txt
                if [ -f $_BANNER_ISSUE_NET ]
                  then
                    cat $_BANNER_ISSUE_NET | head -3 >> _TMP_TELNET.txt
                    if [ `cat $_BANNER_ISSUE_NET | egrep -i "FreeBSD|Linux|Kernel|CentOS|release|Final" | grep -v grep | wc -l` -eq 0 ]
                      then
                        echo "Y" >> $_TMP_FILE1
                      else
                        echo "N" >> $_TMP_FILE1
                    fi
                  else
                    echo "Telnet 서비스 배너 파일이 존재하지 않음" >> _TMP_TELNET.txt
                    echo "N" >> $_TMP_FILE1
                fi
            fi
          else
            echo "Telnet 서비스 중지됨" >> _TMP_TELNET.txt
            echo "Y" >> $_TMP_FILE1
        fi
      else
        echo "Telnet 서비스 중지됨" >> _TMP_TELNET.txt
        echo "Y" >> $_TMP_FILE1
    fi
    
    echo "☞ Telnet 서비스 구동 여부" >> $_TMP_FILE2
    cat _TMP_TELNET.txt >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2
    ;;
  SOLARIS)
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -v "#" | grep "telnet" | wc -l` -gt 0 ]
          then
            echo "telnet enable" >> _TMP_TELNETPS.txt
        fi
    fi
    
    if [ -f _TMP_TELNETPS.txt ]
      then
        cat $_SERVICES | awk '{ if ($1 == "telnet") print $2 }' | grep "tcp" | tr -d "/tcp" >> _TMP_TELNETPT.txt
        if [ `cat _TMP_TELNETPT.txt | wc -l` -gt 0 ]
          then
            _TELNET_PORT=`cat _TMP_TELNETPT.txt | head -1`
          else
            _TELNET_PORT="23"
        fi

        if [ `netstat -an | grep ":$_TELNET_PORT " | wc -l` -gt 0 ]
          then
            echo "Telnet 서비스 실행중" >> _TMP_TELNET.txt
            echo "서비스 : TELNET / 포트 : $_TELNET_PORT" >> _TMP_TELNET.txt
            netstat -an | grep ":$_TELNET_PORT " | head -1 >> _TMP_TELNET.txt
            echo "" >> _TMP_TELNET.txt
    
            echo "☞ Telnet 서비스 배너($_TELNETD_CONF1)" >> _TMP_TELNET.txt
            if [ `cat $_XINETD_CONF | grep -v "#" | grep "telnetd" | grep "\-h" | wc -l` -gt 0 ]
              then
                cat $_XINETD_CONF | grep -v "#" | grep "telnetd" | head -3 >> _TMP_TELNET.txt
                echo "Y" >> $_TMP_FILE1
              elif [ `cat $_TELNETD_CONF1 | grep -v "#" | grep -i "BANNER" | egrep -i "uname" | grep -v grep | wc -l` -eq 0 ]
                then
                  cat $_TELNETD_CONF1 | grep -v "#" | grep -i "BANNER" | head -3 >> _TMP_TELNET.txt
                  echo "Y" >> $_TMP_FILE1
              else
                echo "Telnet 서비스 배너 파일이 존재하지 않음" >> _TMP_TELNET.txt
                echo "N" >> $_TMP_FILE1
            fi
          else
            echo "Telnet 서비스 중지됨" >> _TMP_TELNET.txt
            echo "Y" >> $_TMP_FILE1
        fi
      else
        echo "Telnet 서비스 중지됨" >> _TMP_TELNET.txt
        echo "Y" >> $_TMP_FILE1
    fi
    
    echo "☞ Telnet 서비스 구동 여부" >> $_TMP_FILE2
    cat _TMP_TELNET.txt >> $_TMP_FILE2
    echo "" >> $_TMP_FILE2
    ;;
  *)

esac

echo "0" > $_TMP_FILE3
if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_VSFTPD_CONF1 ]
      then
        cat $_VSFTPD_CONF1 | grep -i "listen_port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            if [ `cat $_VSFTPD_CONF1 | grep -v "#" | grep -i "ftpd_banner" | grep "=" | wc -l` -gt 0  ]
              then
                echo "Y" >> $_TMP_FILE1           
              else
                echo "N" >> $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            echo "서비스 : VSFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt

            echo "☞ FTP 서비스 배너($_VSFTPD_CONF1)" >> _TMP_FTP.txt
            if [ `cat $_VSFTPD_CONF1 | grep -i "ftpd_banner" | wc -l` -gt 0 ]
              then
                cat $_VSFTPD_CONF1 | grep -i "ftpd_banner" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_VSFTPD_CONF2 ]
      then
        cat $_VSFTPD_CONF2 | grep -i "listen_port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            if [ `cat $_VSFTPD_CONF2 | grep -v "#" | grep -i "ftpd_banner" | grep "=" | wc -l` -gt 0  ]
              then
                echo "Y" >> $_TMP_FILE1           
              else
                echo "N" >> $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            echo "서비스 : VSFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt

            echo "☞ FTP 서비스 배너($_VSFTPD_CONF2)" >> _TMP_FTP.txt
            if [ `cat $_VSFTPD_CONF2 | grep -i "ftpd_banner" | wc -l` -gt 0 ]
              then
                cat $_VSFTPD_CONF2 | grep -i "ftpd_banner" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_PROFTPD_CONF1 ]
      then
        cat $_PROFTPD_CONF1 | grep -i "port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            if [ `cat $_PROFTPD_CONF1 | grep -v "#" | grep -i "Serverldent On" | wc -l` -gt 0 -a `cat $_PROFTPD_CONF1 | grep -v "#" | grep -i "Serverldent On" | egrep -i "version|hostname" | wc -l` -eq 0  ]
              then
                echo "Y" >> $_TMP_FILE1           
              else
                echo "N" >> $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            echo "서비스 : PROFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt

            echo "☞ FTP 서비스 배너($_PROFTPD_CONF1)" >> _TMP_FTP.txt
            if [ `cat $_PROFTPD_CONF1 | grep -i "Serverldent" | wc -l` -gt 0 ]
              then
                cat $_PROFTPD_CONF1 | grep -i "Serverldent" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_PROFTPD_CONF2 ]
      then
        cat $_PROFTPD_CONF2 | grep -i "port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            if [ `cat $_PROFTPD_CONF2 | grep -v "#" | grep -i "Serverldent On" | wc -l` -gt 0 -a `cat $_PROFTPD_CONF2 | grep -v "#" | grep -i "Serverldent On" | egrep -i "version|hostname" | wc -l` -eq 0  ]
              then
                echo "Y" >> $_TMP_FILE1           
              else
                echo "N" >> $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            echo "서비스 : PROFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt

            echo "☞ FTP 서비스 배너($_PROFTPD_CONF2)" >> _TMP_FTP.txt
            if [ `cat $_PROFTPD_CONF2 | grep -i "Serverldent" | wc -l` -gt 0 ]
              then
                cat $_PROFTPD_CONF2 | grep -i "Serverldent" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

case $_SERVER_TYPE in
  FREEBSD)
    if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
      then
        if [ -f $_XINETD_CONF ]
          then
            if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "#" | grep -v "tftp" | wc -l` -gt 0 ]
              then
                cat $_SERVICES | awk '{ if ($1 == "ftp") print $2 }' | grep "tcp" | tr -d "/tcp" > _TMP_FTPPT.txt
                if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
                  then
                    _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
                  else
                    _FTP_PORT="21"
                fi
                if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
                  then
                    if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "#" | grep -v "tftp" | grep -i "\-h" | wc -l` -gt 0 ]
                      then
                        echo "Y" >> $_TMP_FILE1           
                      else
                        echo "N" >> $_TMP_FILE1
                    fi
                    echo "FTP 서비스 실행중" > _TMP_FTP.txt
                    echo "서비스 : INETD / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
                    netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
                    echo "" >> _TMP_FTP.txt
    
                    echo "☞ FTP 서비스 배너($_XINETD_CONF)" >> _TMP_FTP.txt
                    if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "tftp" | wc -l` -gt 0 ]
                      then
                        cat $_XINETD_CONF | grep -i "ftp" | grep -v "tftp" >> _TMP_FTP.txt
                      else
                        echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
                    fi
                    echo "1" > $_TMP_FILE3
                fi
            fi
        fi
    fi
    ;;
  SOLARIS)
    if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
      then
        if [ -f $_XINETD_CONF ]
          then
            if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "#" | grep -v "tftp" | wc -l` -gt 0 ]
              then
                cat $_SERVICES | awk '{ if ($1 == "ftp") print $2 }' | grep "tcp" | tr -d "/tcp" > _TMP_FTPPT.txt
                if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
                  then
                    _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
                  else
                    _FTP_PORT="21"
                fi
                if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
                  then
                    if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "#" | grep -v "tftp" | grep -i "\-h" | wc -l` -gt 0 ]
                      then
                        echo "Y" >> $_TMP_FILE1  
                      elif [ `cat $_FTPD_CONF1 | grep -v "#" | grep -i "BANNER" | egrep -i "uname" | grep -v grep | wc -l` -gt 0 ]
                        then
                          echo "Y" >> $_TMP_FILE1  
                      else
                        echo "N" >> $_TMP_FILE1
                    fi
                    echo "FTP 서비스 실행중" > _TMP_FTP.txt
                    echo "서비스 : INETD / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
                    netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
                    echo "" >> _TMP_FTP.txt
    
                    echo "☞ FTP 서비스 배너($_XINETD_CONF)" >> _TMP_FTP.txt
                    if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "tftp" | wc -l` -gt 0 ]
                      then
                        cat $_XINETD_CONF | grep -i "ftp" | grep -v "tftp" >> _TMP_FTP.txt
                        cat $_FTPD_CONF1 | grep -i "BANNER" | grep "=" >> _TMP_FTP.txt
                      else
                        echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
                    fi
                    echo "1" > $_TMP_FILE3
                fi
            fi
        fi
    fi
    ;;
  *)
esac

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    echo "FTP 서비스 중지됨" > _TMP_FTP.txt
    echo "Y" >> $_TMP_FILE1
fi

echo "☞ FTP 서비스 구동 여부" >> $_TMP_FILE2
cat _TMP_FTP.txt >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

if [ -f $_SSH_CONF ]
  then
    cat $_SSH_CONF | grep -i "Port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_SSHPT.txt
    if [ `cat _TMP_SSHPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
      then
        _SSH_PORT=`cat _TMP_SSHPT.txt | head -1`
      else
        _SSH_PORT="22"
    fi
    if [ `netstat -an | grep ":$_SSH_PORT " | wc -l` -gt 0 ]
      then
        echo "SSH 서비스 실행중" > _TMP_SSH.txt
        echo "서비스 : SSH / 포트 : $_SSH_PORT" >> _TMP_SSH.txt
        netstat -an | grep ":$_SSH_PORT " | head -1 >> _TMP_SSH.txt
        echo "" >> _TMP_SSH.txt

        echo "☞ SSH 서비스 배너($_SSH_CONF)" >> _TMP_SSH.txt
        cat $_SSH_CONF | grep -i "banner" >> _TMP_SSH.txt
        if [ `cat $_SSH_CONF | grep -i "^banner" | wc -l` -gt 0  ]
          then
            _SSHBN=`cat $_SSH_CONF | grep -i "^banner" | awk '{print $2}' | head -1`
            if [ -f $_SSHBN ]
              then
                cat $_SSHBN | head -3 >> _TMP_SSH.txt
                if [ `cat $_SSHBN | egrep -i "FreeBSD|Linux|Kernel|CentOS|release|Final" | grep -v grep | wc -l` -eq 0 ]
                  then
                    echo "Y" >> $_TMP_FILE1
                  else
                    echo "N" >> $_TMP_FILE1
                fi
              else
                if [ `cat $_SSH_CONF | grep -i "^banner" | wc -l` -eq 0 ]
                  then
                    echo "N" >> $_TMP_FILE1
                  else
                    echo "Y" >> $_TMP_FILE1
                fi
            fi
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "SSH 서비스 중지됨" >> _TMP_SSH.txt
        echo "Y" >> $_TMP_FILE1 
    fi
  else
    echo "SSH 서비스 중지됨" >> _TMP_SSH.txt
    echo "Y" >> $_TMP_FILE1 
fi

echo "☞ SSH 서비스 구동 여부" >> $_TMP_FILE2
cat _TMP_SSH.txt >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

if [ -f $_SMTP_CONF ]
  then
    cat $_SERVICES | awk '{ if ($1 == "smtp") print $2 }' | grep "tcp" | tr -d "/tcp" > _TMP_SMTPPT.txt
    if [ `cat _TMP_SMTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
      then
        _SMTP_PORT=`cat _TMP_SMTPPT.txt | head -1`
      else
        _SMTP_PORT="25"
    fi
  
    if [ `netstat -an | grep ":$_SMTP_PORT " | wc -l` -gt 0 ]
      then
        echo "SMTP 서비스 실행중" > _TMP_SMTP.txt
        echo "서비스 : SMTP / 포트 : $_SMTP_PORT" >> _TMP_SMTP.txt
        netstat -an | grep ":$_SMTP_PORT " | head -1 >> _TMP_SMTP.txt
        echo "" >> _TMP_SMTP.txt

        echo "☞ SMTP 서비스 배너($_SMTP_CONF)" >> _TMP_SMTP.txt
        cat $_SMTP_CONF | grep -i "O SmtpGreetingMessage" | grep -v "#" >> _TMP_SMTP.txt
        if [ `cat $_SMTP_CONF | grep -v "#" | grep -i "O SmtpGreetingMessage" | wc -l` -gt 0 ]
          then
            if [ `cat $_SMTP_CONF | grep -v "#" | grep -i "O SmtpGreetingMessage" | grep -i "Sendmail" | wc -l` -gt 0 ]
              then
                echo "N" >> $_TMP_FILE1
              elif [ `cat $_SMTP_CONF | grep -v "#" | grep -i "O SmtpGreetingMessage" | grep -i "\$v" | wc -l` -gt 0 ]
                then
                  echo "N" >> $_TMP_FILE1
              elif [ `cat $_SMTP_CONF | grep -v "#" | grep -i "O SmtpGreetingMessage" | grep -i "\$Z" | wc -l` -gt 0 ]
                then
                  echo "N" >> $_TMP_FILE1
              elif [ `cat $_SMTP_CONF | grep -v "#" | grep -i "O SmtpGreetingMessage" | grep -i "\$b" | wc -l` -gt 0 ]
                then
                  echo "N" >> $_TMP_FILE1
              else
                echo "Y" >> $_TMP_FILE1
            fi
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "SMTP 서비스 중지됨" >> _TMP_SMTP.txt
        echo "Y" >> $_TMP_FILE1 
    fi
  else
    echo "SMTP 서비스 중지됨" >> _TMP_SMTP.txt
    echo "Y" >> $_TMP_FILE1 
fi

echo "☞ SMTP 서비스 구동 여부" >> $_TMP_FILE2
cat _TMP_SMTP.txt >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_16=Y
    _CHK_A_16="서비스 배너에 버전 정보를 제공하고 있지 않음" 
  else 
    _CHK_R_16=N
    _CHK_A_16="서비스 배너에 버전 정보를 제공하고 있음" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_16=`cat $_STATE_FILE1`
    
    echo $_CHK_S_16 >> $_TMP_FILE4
    echo $_CHK_A_16 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_16=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_16=`cat $_STATE_FILE1`
    
    echo $_CHK_S_16 >> $_TMP_FILE4
    echo $_CHK_A_16 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_16=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1
rm -rf _TMP_TELNETPS.txt
rm -rf _TMP_TELNETPT.txt
rm -rf _TMP_TELNETBN.txt
rm -rf _TMP_TELNET.txt
rm -rf _TMP_FTPPS.txt
rm -rf _TMP_FTPPT.txt
rm -rf _TMP_FTP.txt
rm -rf _TMP_SSHPS.txt
rm -rf _TMP_SSH.txt
rm -rf _TMP_SSHPT.txt
rm -rf _TMP_SMTPPS.txt
rm -rf _TMP_SMTP.txt
rm -rf _TMP_SMTPPT.txt
rm -rf _TMP_DNSPS.txt
rm -rf _TMP_DNS.txt
rm -rf _TMP_DNSPT.txt
rm -rf _TMP_SERVERBN.txt

echo "■ 현황" >> $_TMP_FILE2

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    ps -aux | grep inetd  | grep -v grep >> _TMP_XINETPS.txt  
    ;;
  SOLARIS) 
    ps -ef | grep inetd  | grep -v grep >> _TMP_XINETPS.txt  
    ;;
  *)
esac

if [ `cat _TMP_XINETPS.txt | grep inetd | grep -v grep | wc -l` -gt 0 ]
  then
    _SERVICE_RPC="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"
  else
    _SERVICE_RPC="nullvalue|nullvalue"
fi

if [ -f $_XINETD_CONF ]
  then
    if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_RPC | wc -l` -eq 0 ]
      then
        echo "Y" >> $_TMP_FILE1
      else
        echo "N" >> $_TMP_FILE1
    fi
  else
    echo "Y" >> $_TMP_FILE1
fi

echo "☞ 불필요한 RPC 서비스 목록" >> $_TMP_FILE2
if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_RPC | wc -l` -gt 0 ]
  then
    cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_RPC >> $_TMP_FILE2
  else
    echo "N/A" >> $_TMP_FILE2
fi

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_17=Y
    _CHK_A_17="불필요한 RPC 서비스가 존재하지 않음" 
  else 
    _CHK_R_17=N
    _CHK_A_17="불필요한 RPC 서비스가 존재함" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_17=`cat $_STATE_FILE1`
    
    echo $_CHK_S_17 >> $_TMP_FILE4
    echo $_CHK_A_17 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_17=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_17=`cat $_STATE_FILE1`
    
    echo $_CHK_S_17 >> $_TMP_FILE4
    echo $_CHK_A_17 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_17=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1
rm -rf _TMP_XINETPS.txt

echo "■ 현황" >> $_TMP_FILE2

_SERVICE_R="rsh|rlogin|rexec|rshell|rcp|rcmd|shell|login|exec"

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    if [ -d $_XINETD_D ]
      then
        if [ `ls -alL $_XINETD_D | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
          then
            for _403 in `ls -alL $_XINETD_D | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
            do
              if [ `cat $_XINETD_D/$_403 | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
                then
                  echo "N" >> $_TMP_FILE1
                else
                   echo "Y" >> $_TMP_FILE1
              fi
            done
          else
            echo "Y" >> $_TMP_FILE1
        fi
      elif [ -f $_XINETD_CONF ]
        then
          if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
            then
              echo "Y" >> $_TMP_FILE1
            else
              echo "N" >> $_TMP_FILE1
          fi
      else
        echo "Y" >> $_TMP_FILE1
    fi

    ;;
  FREEBSD|SOLARIS)
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -v '#' | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "Y" >> $_TMP_FILE1
    fi

    ;;
  *)
esac

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    echo "☞ 시스템에 존재하는 R 서비스" >> $_TMP_FILE2
    if [ `ls -alL $_XINETD_D/* | egrep $_SERVICE_R |egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
      then
        ls -alL $_XINETD_D/* | egrep $_SERVICE_R  >> $_TMP_FILE2
      else
        echo "시스템에 존재하는 R 서비스가 없음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    echo "☞ $_XINETD_D 내용" >> $_TMP_FILE2
    if [ `ls -alL $_XINETD_D | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
      then
        for _403 in `ls -alL $_XINETD_D | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
        do
          echo " $_403 파일" >> $_TMP_FILE2
          cat $_XINETD_D/$_403 | grep -i "disable" >> $_TMP_FILE2
          echo "" >> $_TMP_FILE2
        done
      else
        echo "$_XINETD_D에 R 서비스 파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    echo "☞ $_XINETD_CONF 파일" >> $_TMP_FILE2
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" |wc -l` -gt 0 ]
          then
            cat $_XINETD_CONF | grep -v "^ *#" | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" >> $_TMP_FILE2
          else
            echo "$_XINETD_CONF 파일에 R 서비스 항목이 존재하지 않음" >> $_TMP_FILE2
        fi
      else
        echo "$_XINETD_CONF 파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    ;;
  FREEBSD|SOLARIS)
    echo "☞ $_XINETD_CONF 파일" >> $_TMP_FILE2
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -v '#' | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" |wc -l` -gt 0 ]
          then
            cat $_XINETD_CONF | grep -v "#" | egrep $_SERVICE_R | egrep -v "grep|klogin|kshell|kexec" >> $_TMP_FILE2
          else
            echo "$_XINETD_CONF 파일에 R 서비스 항목이 존재하지 않음" >> $_TMP_FILE2
        fi
      else
        echo "$_XINETD_CONF 파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    ;;
  *)
esac
  
if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_18=Y
    _CHK_A_18="불필요한 R 서비스가 구동중이지 않음" 
  else 
    _CHK_R_18=N
    _CHK_A_18="불필요한 R 서비스가 구동중임" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_18=`cat $_STATE_FILE1`
    
    echo $_CHK_S_18 >> $_TMP_FILE4
    echo $_CHK_A_18 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_18=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_18=`cat $_STATE_FILE1`
    
    echo $_CHK_S_18 >> $_TMP_FILE4
    echo $_CHK_A_18 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_18=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

_HOME_DIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
_RHOSTS_FILE="/.rhosts"
if [ -f $_HOSTS_EQUIV ]
  then
    if [ `cat $_HOSTS_EQUIV | grep "+" | grep -v "grep" | grep -v "#" | wc -l ` -eq 0 ]
      then
        echo "Y" >> $_TMP_FILE1
      else
        echo "N" >> $_TMP_FILE1
    fi
  else
    echo "Y" >> $_TMP_FILE1
fi

for _404_DIR in $_HOME_DIRS
do
  for _404_FILE in $_RHOSTS_FILE
  do
    if [ -f $_404_DIR$_404_FILE ]
      then
        if [ `cat $_404_DIR$_404_FILE | grep "+" | grep -v "grep" | grep -v "#" |wc -l ` -eq 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "Y" >> $_TMP_FILE1
    fi
  done
done

echo "☞ $_HOSTS_EQUIV 설정" >> $_TMP_FILE2
if [ -f $_HOSTS_EQUIV ]
  then
    cat $_HOSTS_EQUIV >> $_TMP_FILE2
  else
    echo "파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

echo "☞ 홈 디렉토리 내 $_RHOSTS_FILE 설정" >> $_TMP_FILE2
for _404_DIR in $_HOME_DIRS
do
  for _404_FILE in $_RHOSTS_FILE
  do
    if [ -f $_404_DIR$_404_FILE ]
      then
        echo "true" >> $_TMP_FILE3
        echo "- $_404_DIR$_404_FILE" >> $_TMP_FILE2
        cat $_404_DIR$_404_FILE | grep -v "#" >> $_TMP_FILE2
        echo "" >> $_TMP_FILE2
    fi
  done
done

if [ ! -f $_TMP_FILE3 ]
  then
    echo "파일이 존재하지 않음" >> $_TMP_FILE2
fi

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_19=Y
    _CHK_A_19="불필요한 R 서비스가 구동중이지 않거나 관련 파일이 존재하지 않음" 
  else 
    _CHK_R_19=N
    _CHK_A_19="R 서비스 관련 파일이 존재하거나 설정이 부적합함" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_19=`cat $_STATE_FILE1`
    
    echo $_CHK_S_19 >> $_TMP_FILE4
    echo $_CHK_A_19 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_19=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_19=`cat $_STATE_FILE1`
    
    echo $_CHK_S_19 >> $_TMP_FILE4
    echo $_CHK_A_19 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_19=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

echo "0" > $_TMP_FILE3
if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_VSFTPD_CONF1 ]
      then
        cat $_VSFTPD_CONF1 | grep -i "listen_port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            if [ `cat $_VSFTPD_CONF1 | grep -i "anonymous_enable" | grep -v "#" | grep -i "YES" | wc -l` -gt 0  ]
              then
                echo "N" > $_TMP_FILE1           
              else
                echo "Y" > $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            ps -ef | grep -i "vsftp" | grep -v "grep" | head -3 >> _TMP_FTP.txt
            echo "서비스 : VSFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt
            echo "☞ 익명 FTP" >> _TMP_FTP.txt
            if [ `cat $_VSFTPD_CONF1 | grep -i "anonymous_enable" | wc -l` -gt 0 ]
              then
                cat $_VSFTPD_CONF1 | grep -i "anonymous_enable" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_VSFTPD_CONF2 ]
      then
        cat $_VSFTPD_CONF2 | grep -i "listen_port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            if [ `cat $_VSFTPD_CONF2 | grep -i "anonymous_enable" | grep -v "#" | grep -i "YES" | wc -l` -gt 0  ]
              then
                echo "N" > $_TMP_FILE1           
              else
                echo "Y" > $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            ps -ef | grep -i "vsftp" | grep -v "grep" | head -3 >> _TMP_FTP.txt
            echo "서비스 : VSFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt
            echo "☞ 익명 FTP" >> _TMP_FTP.txt
            if [ `cat $_VSFTPD_CONF2 | grep -i "anonymous_enable" | wc -l` -gt 0 ]
              then
                cat $_VSFTPD_CONF2 | grep -i "anonymous_enable" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_PROFTPD_CONF1 ]
      then
        cat $_PROFTPD_CONF1 | grep -i "port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            _FTP_USER=`cat $_PROFTPD_CONF1 | grep -i "^user" | awk '{print $2}' | head -1`
            if [ `cat $_PROFTPD_CONF1 | grep -i "<Anonymous " | grep -v "#" | wc -l` -gt 0 ]
              then
                if [ `cat $_PASSWD | grep -v "^ *#" | grep "$_FTP_USER" | wc -l` -gt 0 ]
                  then
                    echo "N" > $_TMP_FILE1
                  else
                    echo "Y" > $_TMP_FILE1
                fi
              else
                echo "Y" > $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            ps -ef | grep -i "proftp" | grep -v "grep" | head -3 >> _TMP_FTP.txt
            echo "서비스 : PROFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt
            echo "☞ 익명 FTP" >> _TMP_FTP.txt
            if [ `cat $_PROFTPD_CONF1 | grep -i "<Anonymous " | wc -l` -gt 0 ]
              then
                cat $_PROFTPD_CONF1 | grep -i "<Anonymous " >> _TMP_FTP.txt
                cat $_PASSWD | grep "$_FTP_USER" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_PROFTPD_CONF2 ]
      then
        cat $_PROFTPD_CONF2 | grep -i "port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="21"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            _FTP_USER=`cat $_PROFTPD_CONF2 | grep -i "^user" | awk '{print $2}' | head -1`
            if [ `cat $_PROFTPD_CONF2 | grep -i "<Anonymous " | grep -v "#" | wc -l` -gt 0 ]
              then
                if [ `cat $_PASSWD | grep -v "^ *#" | grep "$_FTP_USER" | wc -l` -gt 0 ]
                  then
                    echo "N" > $_TMP_FILE1
                  else
                    echo "Y" > $_TMP_FILE1
                fi
              else
                echo "Y" > $_TMP_FILE1
            fi
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            ps -ef | grep -i "proftp" | grep -v "grep" | head -3 >> _TMP_FTP.txt
            echo "서비스 : PROFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            echo "" >> _TMP_FTP.txt
            echo "☞ 익명 FTP" >> _TMP_FTP.txt
            if [ `cat $_PROFTPD_CONF2 | grep -i "<Anonymous " | wc -l` -gt 0 ]
              then
                cat $_PROFTPD_CONF2 | grep -i "<Anonymous " >> _TMP_FTP.txt
                cat $_PASSWD | grep "$_FTP_USER" >> _TMP_FTP.txt
              else
                echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
            fi
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_SSH_CONF ]
      then
        cat $_SSH_CONF | grep -i "port" | grep -v "#" | sed 's/[^0-9]//g' > _TMP_FTPPT.txt
        if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
          then
            _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
          else
            _FTP_PORT="22"
        fi
        if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
          then
            echo "Y" > $_TMP_FILE1
            echo "FTP 서비스 실행중" > _TMP_FTP.txt
            netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
            ps -ef | grep -i "sftp-server" | grep -v "grep" | head -3 >> _TMP_FTP.txt
            echo "서비스 : SFTP / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
            echo "1" > $_TMP_FILE3
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "#" | grep -v "tftp" | wc -l` -gt 0  ]
          then
            cat $_SERVICES | awk '{ if ($1 == "ftp") print $2 }' | grep "tcp" | tr -d "/tcp" > _TMP_FTPPT.txt
            if [ `cat _TMP_FTPPT.txt | grep "[0-9]" | wc -l` -gt 0 ]
              then
                _FTP_PORT=`cat _TMP_FTPPT.txt | head -1`
              else
                _FTP_PORT="21"
            fi
            if [ `netstat -an | grep ":$_FTP_PORT " | wc -l` -gt 0 ]
              then
                if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "#" | grep -v "tftp" | grep -i "\-A" | wc -l` -gt 0  ]
                  then
                    echo "N" > $_TMP_FILE1           
                  else
                    echo "Y" > $_TMP_FILE1
                fi
                echo "FTP 서비스 실행중" > _TMP_FTP.txt
                netstat -an | grep ":$_FTP_PORT " | head -1 >> _TMP_FTP.txt
                ps -ef | grep -i "ftp" | grep -v "grep" | head -3 >> _TMP_FTP.txt
                echo "서비스 : INETD / 포트 : $_FTP_PORT" >> _TMP_FTP.txt
                echo "" >> _TMP_FTP.txt
                echo "☞ 익명 FTP" >> _TMP_FTP.txt
                if [ `cat $_XINETD_CONF | grep -i "ftp" | grep -v "tftp" | wc -l` -gt 0 ]
                  then
                    cat $_XINETD_CONF | grep -i "ftp" | grep -v "tftp" >> _TMP_FTP.txt
                  else
                    echo "설정 값이 존재하지 않음" >> _TMP_FTP.txt
                fi
                echo "1" > $_TMP_FILE3
            fi
        fi
    fi
fi

if [ `cat $_TMP_FILE3 | grep "0" | wc -l` -gt 0 ]
  then
    echo "FTP 서비스 중지됨" > _TMP_FTP.txt
    echo "Y" > $_TMP_FILE1
fi

echo "☞ FTP 서비스 구동 여부" >> $_TMP_FILE2 
cat _TMP_FTP.txt >> $_TMP_FILE2 

if [ `cat $_TMP_FILE1 | egrep "Y" | wc -l` -gt 0 ]
  then
    _CHK_R_20=Y
    _CHK_A_20="FTP 서비스가 중지되어 있거나 익명 FTP를 허용하지 않도록 설정되어 있음" 
fi

if [ `cat $_TMP_FILE1 | egrep "N" | wc -l` -gt 0 ]
  then
    _CHK_R_20=N
    _CHK_A_20="FTP 서비스가 실행중이고, 익명 FTP를 허용하도록 설정되어 있음" 
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_20=`cat $_STATE_FILE1`
    
    echo $_CHK_S_20 >> $_TMP_FILE4
    echo $_CHK_A_20 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_20=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_20=`cat $_STATE_FILE1`
    
    echo $_CHK_S_20 >> $_TMP_FILE4
    echo $_CHK_A_20 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_20=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1
rm -rf _TMP_FTPPS.txt
rm -rf _TMP_FTP.txt
rm -rf _TMP_FTPPT.txt

echo "■ 현황" >> $_TMP_FILE2

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    if [ -f $_SECURETTY_CONF ]
      then
        if [ `grep "pts" $_SECURETTY_CONF | grep -v '#' | wc -l` -ge 1 ]
          then
            echo "N" >> $_TMP_FILE1
          else
            echo "Y" >> $_TMP_FILE1
        fi
      else
        echo "N" >> $_TMP_FILE1
    fi

    if [ -f $_LOGIN_PAM ]
      then
        if [ `grep "pam_securetty.so" $_LOGIN_PAM | grep -v '#' | wc -l` -eq 1 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "N" >> $_TMP_FILE1
    fi
    ;;
  FREEBSD)
    if [ -f $_LOGIN_PAM ]
      then
        if [ `grep "pam_securetty.so" $_LOGIN_PAM | grep -v '#' | wc -l` -eq 1 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "N" >> $_TMP_FILE1
    fi
    ;;
  SOLARIS)
    if [ -f $_LOGIN_CONF ]
      then
        if [ `grep -i "^CONSOLE" $_LOGIN_CONF | grep -v '#' | wc -l` -eq 1 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "N" >> $_TMP_FILE1
    fi
    ;;
  *)
esac

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    echo "☞ $_SECURETTY_CONF 파일 설정" >> $_TMP_FILE2
    if [ -f $_SECURETTY_CONF ]
      then
        if [ `grep "pts" $_SECURETTY_CONF | wc -l` -gt 0 ]
          then
            cat $_SECURETTY_CONF | grep "pts" >> $_TMP_FILE2
          else
            echo "pts 설정이 제거되어 있음" >> $_TMP_FILE2
        fi
      else
        echo "파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    echo "☞ $_LOGIN_PAM 파일 설정" >> $_TMP_FILE2
    if [ -f $_LOGIN_PAM ]
      then
        if [ `grep "pam_securetty.so" $_LOGIN_PAM | wc -l` -gt 0 ]
          then
            cat $_LOGIN_PAM | grep "pam_securetty.so" >> $_TMP_FILE2
          else
            echo "설정 값이 존재하지 않음" >> $_TMP_FILE2
        fi
      else
        echo "파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2
    ;;
  FREEBSD)
    echo "☞ $_LOGIN_PAM 파일 설정" >> $_TMP_FILE2
    if [ -f $_LOGIN_PAM ]
      then
        if [ `grep "pam_securetty.so" $_LOGIN_PAM | wc -l` -gt 0 ]
          then
            cat $_LOGIN_PAM | grep "pam_securetty.so" >> $_TMP_FILE2
          else
            echo "설정 값이 존재하지 않음" >> $_TMP_FILE2
        fi
      else
        echo "파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2
    ;;
  SOLARIS)
    echo "☞ $_LOGIN_CONF 파일 설정" >> $_TMP_FILE2
    if [ -f $_LOGIN_CONF ]
      then
        if [ `grep "^CONSOLE" $_LOGIN_CONF | wc -l` -gt 0 ]
          then
            cat $_LOGIN_CONF | grep "CONSOLE" >> $_TMP_FILE2
          else
            echo "설정 값이 존재하지 않음" >> $_TMP_FILE2
        fi
      else
        echo "파일이 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2
    ;;
  *)
esac

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_21=Y
    _CHK_A_21="Telnet의 root 접근 제한 설정이 되어 있음" 
  else 
    _CHK_R_21=N
    _CHK_A_21="Telnet의 root 접근 제한 설정이 되어 있지 않음" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_21=`cat $_STATE_FILE1`
    
    echo $_CHK_S_21 >> $_TMP_FILE4
    echo $_CHK_A_21 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_21=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_21=`cat $_STATE_FILE1`
    
    echo $_CHK_S_21 >> $_TMP_FILE4
    echo $_CHK_A_21 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_21=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2
echo "☞ SNMP 서비스 동작 여부" >> $_TMP_FILE2

if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "SNMP 서비스가 비실행중" >> $_TMP_FILE2
  else
    ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | head -3 >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ -f $_SNMPD_CONF1 ]
  then
    _SNMPD_CONF_FILE=$_SNMPD_CONF1
  elif [ -f $_SNMPD_CONF2 ]
    then
      _SNMPD_CONF_FILE=$_SNMPD_CONF2
  elif [ -f $_SNMPD_CONF3 ]
    then
      _SNMPD_CONF_FILE=$_SNMPD_CONF3
  elif [ -f $_SNMPD_CONF4 ]
    then
      _SNMPD_CONF_FILE=$_SNMPD_CONF4
  elif [ -f $_SNMPD_CONF5 ]
    then
      _SNMPD_CONF_FILE=$_SNMPD_CONF5
  else
    _SNMPD_CONF_FILE="111111111111111"
fi

echo "☞ SNMPD_CONF 파일($_SNMPD_CONF_FILE)" >> $_TMP_FILE2
if [ -f $_SNMPD_CONF_FILE ]
  then
    grep -v '^ *#' $_SNMPD_CONF_FILE | egrep -i "public|private" | egrep -v "group|trap" >> $_TMP_FILE2
  else
    echo "SNMPD_CONF 파일이 존재하지 않음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "Y" >> $_TMP_FILE1
  else
    if [ -f $_SNMPD_CONF_FILE ]
      then
        if [ `cat $_SNMPD_CONF_FILE | egrep -i "public|private" | grep -v "#" | egrep -v "group|trap" | wc -l ` -eq 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
    else
      echo "SELF" >> $_TMP_FILE1
    fi
fi

if [ `cat $_TMP_FILE1 | egrep "Y|N" | wc -l` -gt 0 ]
  then
    if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
      then
        _CHK_R_22=Y
        _CHK_A_22="SNMP 서비스가 중지되어 있거나 디폴트 커뮤니티 스트링 값을 사용하고 있지 않음" 
      else
        _CHK_R_22=N
        _CHK_A_22="SNMP 서비스가 동작중이며 디폴트 커뮤니티 스트링 값을 사용하고 있음" 
    fi
  else
    _CHK_R_22=SELF
    _CHK_A_22="사용중인 SNMP 서비스 확인 후 설정 확인 필요" 
fi

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_22=`cat $_STATE_FILE1`
    
    echo $_CHK_S_22 >> $_TMP_FILE4
    echo $_CHK_A_22 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_22=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_22=`cat $_STATE_FILE1`
    
    echo $_CHK_S_22 >> $_TMP_FILE4
    echo $_CHK_A_22 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_22=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

_FLAGS="true"
_SERVICE_INETD="echo|discard|daytime|chargen|time|tftp|finger|sftp|uucp-path|nntp|ntp|netbios_ns|netbios_dgm|netbios_ssn|bftp|ldap|printer|talk|ntalk|uucp|pcserver|ldaps|ingreslock|www-ldap-gw|nfsd|dtspcd"

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_INETD | wc -l ` -eq 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "Y" >> $_TMP_FILE1
    fi

    if [ -d $_XINETD_D ]
      then
        if [ `ls -alL $_XINETD_D | egrep $_SERVICE_INETD | wc -l` -gt 0 ]
          then
            for _VVV in `ls -alL $_XINETD_D | egrep $_SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
            do
              if [ `cat $_XINETD_D/$_VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
                then
                  echo "N" >> $_TMP_FILE1
                else
                  echo "Y" >> $_TMP_FILE1
              fi
            done
          else
            echo "Y" >> $_TMP_FILE1
        fi
      else
        echo "Y" >> $_TMP_FILE1
    fi

    ;;
  FREEBSD|SOLARIS)
    if [ -f $_XINETD_CONF ]
      then
        if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_INETD | wc -l ` -eq 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        echo "Y" >> $_TMP_FILE1
    fi

    ;;
  *)
esac

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    echo "☞ $_XINETD_CONF 파일 내의 불필요한 서비스 목록" >> $_TMP_FILE2
    if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_INETD | wc -l ` -gt 0 ]
      then
        cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_INETD >> $_TMP_FILE2
      else
        echo "$_XINETD_CONF 파일 내의 불필요한 서비스가 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    echo "☞ $_XINETD_D 디렉토리 내의 불필요한 서비스 목록" >> $_TMP_FILE2
    if [ `ls -alL $_XINETD_D/* | egrep $_SERVICE_INETD | wc -l` -gt 0 ]
      then
        ls -alL $_XINETD_D/* | egrep $_SERVICE_INETD >> $_TMP_FILE2
      else
        echo "$_XINETD_D 디렉토리 내의 불필요한 서비스가 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    echo "☞ $_XINETD_D 디렉토리 내의 활성화 된 불필요한 서비스 목록" >> $_TMP_FILE2
    if [ `ls -alL $_XINETD_D | egrep $_SERVICE_INETD | wc -l` -gt 0 ]
      then
        for _VVV in `ls -alL $_XINETD_D | egrep $_SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
          if [ `cat $_XINETD_D/$_VVV | grep -i "disable" | grep -i "no" | grep -v "#" | wc -l` -gt 0 ]
            then
              _FLAGS="false"
              echo " $_VVV 파일" >> $_TMP_FILE2
              cat $_XINETD_D/$_VVV | grep -i "disable" >> $_TMP_FILE2
              echo "" >> $_TMP_FILE2
          fi          
        done
    fi

    if [ $_FLAGS = "true" ]
      then
        echo "활성화 된 불필요한 서비스 없음" >> $_TMP_FILE2
        echo "" >> $_TMP_FILE2
    fi

    ;;
  FREEBSD|SOLARIS)
    echo "☞ $_XINETD_CONF 파일 내의 불필요한 서비스 목록" >> $_TMP_FILE2
    if [ `cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_INETD | wc -l ` -gt 0 ]
      then
        cat $_XINETD_CONF | grep -v '^ *#' | egrep $_SERVICE_INETD >> $_TMP_FILE2
      else
        echo "$_XINETD_CONF 파일 내의 불필요한 서비스가 존재하지 않음" >> $_TMP_FILE2
    fi
    echo "" >> $_TMP_FILE2

    ;;
  *)
esac

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_23=Y
    _CHK_A_23="불필요한 서비스가 존재하지 않음" 
  else 
    _CHK_R_23=N
    _CHK_A_23="불필요한 서비스가 존재함" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_23=`cat $_STATE_FILE1`
    
    echo $_CHK_S_23 >> $_TMP_FILE4
    echo $_CHK_A_23 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_23=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_23=`cat $_STATE_FILE1`
    
    echo $_CHK_S_23 >> $_TMP_FILE4
    echo $_CHK_A_23 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_23=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

if [ -f $_SYSLOG_CONF_FILE ]
  then
    if [ `ls -al $_SYSLOG_CONF_FILE | grep "syslog-ng" | wc -l` -gt 0 ]
      then
        if [ `cat $_SYSLOG_CONF_FILE | egrep -i "authpriv|auth" | grep -v "#" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        if [ `cat $_SYSLOG_CONF_FILE | egrep -i "authpriv\.|auth\." | grep -v "#" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
    fi
  else
    echo "N" >> $_TMP_FILE1
fi

echo "☞ SYSLOG_CONF_FILE($_SYSLOG_CONF_FILE) 파일 점검" >> $_TMP_FILE2
if [ -f $_SYSLOG_CONF_FILE ]
  then
    if [ `ls -al $_SYSLOG_CONF_FILE | grep "syslog-ng" | wc -l` -gt 0 ]
      then
        cat $_SYSLOG_CONF_FILE | egrep -i "authpriv|auth" | grep -v "#" >> $_TMP_FILE2
      else
        cat $_SYSLOG_CONF_FILE | egrep -i "authpriv\.|auth\." | grep -v "#" >> $_TMP_FILE2
    fi
  else
    echo "SYSLOG_CONF_FILE($_SYSLOG_CONF_FILE) 파일 없음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_24=Y
    _CHK_A_24="인증관련 로그를 기록하고 있음" 
  else 
    _CHK_R_24=N
    _CHK_A_24="파일이 존재하지 않거나 인증관련 로그를 기록하고 있지 않음" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_24=`cat $_STATE_FILE1`
    
    echo $_CHK_S_24 >> $_TMP_FILE4
    echo $_CHK_A_24 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_24=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_24=`cat $_STATE_FILE1`
    
    echo $_CHK_S_24 >> $_TMP_FILE4
    echo $_CHK_A_24 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_24=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

if [ -f $_SYSLOG_CONF_FILE ]
  then
    if [ `ls -al $_SYSLOG_CONF_FILE | grep "syslog-ng" | wc -l` -gt 0 ]
      then
        if [ `cat $_SYSLOG_CONF_FILE | grep -i "level" | egrep -i "info" | grep -v "#" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi

        if [ `cat $_SYSLOG_CONF_FILE | grep -i "level" | egrep -i "emerg" | grep -v "#" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi

        if [ `cat $_SYSLOG_CONF_FILE | grep -i "level" | egrep -i "crit" | grep -v "#" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
      else
        if [ `cat $_SYSLOG_CONF_FILE | egrep "info|alert|notice|debug" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
        
        if [ `cat $_SYSLOG_CONF_FILE | egrep "alert|err|crit" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
        
        if [ `cat $_SYSLOG_CONF_FILE | grep "emerg" | grep "\*" | wc -l` -gt 0 ]
          then
            echo "Y" >> $_TMP_FILE1
          else
            echo "N" >> $_TMP_FILE1
        fi
    fi
  else
    echo "N" >> $_TMP_FILE1
fi

echo "☞ syslog 프로세스" >> $_TMP_FILE2
case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    ps -aux | grep 'syslog' | grep -v 'grep' | head -3 >> $_TMP_FILE2 
    ;;
  SOLARIS) 
    ps -ef | grep 'syslog' | grep -v 'grep' | head -3 >> $_TMP_FILE2 
    ;;
  *)
esac
echo "" >> $_TMP_FILE2

echo "☞ 시스템 로깅 설정" >> $_TMP_FILE2
if [ -f $_SYSLOG_CONF_FILE ]
  then
    if [ `ls -al $_SYSLOG_CONF_FILE | grep "syslog-ng" | wc -l` -gt 0 ]
      then
        cat $_SYSLOG_CONF_FILE | grep -v "#" | head -20 >> $_TMP_FILE2
        echo "   중략   " >> $_TMP_FILE2
      else
        cat $_SYSLOG_CONF_FILE | grep -v "#" | grep -v '^ *$' | head -20 >> $_TMP_FILE2
        echo "   중략   " >> $_TMP_FILE2
    fi
  else
    echo "SYSLOG_CONF_FILE 파일 없음" >> $_TMP_FILE2
fi
echo "" >> $_TMP_FILE2

if [ `cat $_TMP_FILE1 | grep "N" | wc -l` -eq 0 ]
  then 
    _CHK_R_25=Y
    _CHK_A_25="중요 정보에 대한 로그를 기록하고 있음" 
  else 
    _CHK_R_25=N
    _CHK_A_25="중요 정보에 대한 로그를 기록하고 있지 않음" 
fi 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_25=`cat $_STATE_FILE1`
    
    echo $_CHK_S_25 >> $_TMP_FILE4
    echo $_CHK_A_25 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_25=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_25=`cat $_STATE_FILE1`
    
    echo $_CHK_S_25 >> $_TMP_FILE4
    echo $_CHK_A_25 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_25=`cat $_STATE_FILE1`
    ;;
  *)
esac

rm -rf $_TMP_FILE1
rm -rf $_TMP_FILE2
rm -rf $_TMP_FILE3
rm -rf $_TMP_FILE4
rm -rf $_STATE_FILE1

echo "■ 현황" >> $_TMP_FILE2

echo "☞ 서버 버전" >> $_TMP_FILE2
echo $_SERVER_INFO >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

echo "☞ 커널 버전" >> $_TMP_FILE2
echo $_KERNEL_INFO >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

echo "☞ OpenSSL" >> $_TMP_FILE2
openssl version -a | egrep "^OpenSSL|^built" >> $_TMP_FILE2
echo "" >> $_TMP_FILE2

echo "☞ Bash" >> $_TMP_FILE2
bash --version 2> /dev/null | grep -i "version" | grep -i "bash" >> $_TMP_FILE2 2> /dev/null
echo "" >> $_TMP_FILE2

_CHK_R_26=SELF
_CHK_A_26="수동 또는 인터뷰" 

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_26=`cat $_STATE_FILE1`
    
    echo $_CHK_S_26 >> $_TMP_FILE4
    echo $_CHK_A_26 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\r\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_26=`cat $_STATE_FILE1`
    ;;
  SOLARIS)
    cat $_TMP_FILE2 | tr '\\' '/' | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_S_26=`cat $_STATE_FILE1`
    
    echo $_CHK_S_26 >> $_TMP_FILE4
    echo $_CHK_A_26 >> $_TMP_FILE4
    cat $_TMP_FILE4 | tr '\n' '\\' | tr ',' ' ' > $_STATE_FILE1
    _CHK_SA_26=`cat $_STATE_FILE1`
    ;;
  *)
esac

_FINAL_RES_1=`echo eQLQLQAABWY_AAB_AY_CAB_A_TMP_TWdB4Y_AY_AR_A_TMP_LE4Y_CAAAB_AY_AALS11 VKDKESOdDL__TMP_TWdB4TMP_TWdB4DLDLWL__TMP_TWdB426_VKDKE_A_TMP_TWdB4F_AJ_EGC_AY_AR_AAB_AY_AAB_AY_TMP_TWdB4Y_AA_MACSAB_A_TMP_TWdB_TMP_TWdB4Y_AA_MACS4Y_CAHL_CREY_AAB_AY_TMP_TWdB4Y_AA_MACS_CAAB_AY_AAATE_TWdB_TMP_F__TMP_TWdB4Y_AA_MACSTMP_TWdB_TMP_TWdB4Y_AA_MACS4LE4_WOdU_TMP_TWdB4Y_AA_MACSKSLS_CWAB_A_TMP_TWdB4Y_CAK_AAB_AHL_CREA_TMP_TWdB4Y_A_TMP_TWdB4Y_AA_TMP_TWdB4Y_AA_MACS_MACSA_MACSTH_TMP_TWdB4Y_AA_MACSAB_A__TMP_TWdB4Y_AA_M_TMP_TWdB4Y_TMP_TWdB4Y_AA__TMP_TWdB4Y_AA_MACSMACS_AA_MACSACSTMP_TWdB4Y_CAL_CREAAB_A_TMP_TWdB4Y_CATE_TWdB_WOdUE__TMP__TMP_TWdB4TWdB4TWdB_HL_C_TMP_TWdB4REATE_TWdB_WOdUWOdULT_TOTALWWLS11KS_EGBY_AAB_AY_CAAB_A_TMP_TWdB4Y_AAA_TMP_TWdB4Y_AA_MACSCDAY_AABY_AAB_AY_CAAB_WOd_AY_AA_ADKDY_AAB__AB_A_TMP_TWdB4Y_CAWOdAY_ABTWdB_WOdULT_TAR_A_TMP_TWdB4AB_A_TMP_TWdB4Y_CAY_CA_TMP_TWdB4CAAB_AY_AAKAB__WOd_CH_TMPY_AAB_A_TMP__TMP_TWdB4Y_AA_MACSFI_TMP_TWdB4Y_AA_MACSLE4Y_TMP_TWdB4Y_AA_MACS_CAAB_A_TMP_TWdB4Y_AA_MACSLDTK_RK`

rm -rf $_TMP_FILE1;rm -rf $_TMP_FILE2;rm -rf $_TMP_FILE3;rm -rf $_TMP_FILE4;rm -rf $_STATE_FILE1;_CREATE_FILE_TEST_RESULT=${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}_res.txt;echo "● 서버 종류 : $_SERVER_TYPE">$_CREATE_FILE_TEST_RESULT;echo "● 아이피 주소 : $_IP">>$_CREATE_FILE_TEST_RESULT;echo "● 하드웨어 주소 : $_MAC">>$_CREATE_FILE_TEST_RESULT;echo "● 호스트 이름 : $_HOSTNAME">>$_CREATE_FILE_TEST_RESULT;echo "● 서버 정보 : $_SERVER_INFO">>$_CREATE_FILE_TEST_RESULT;echo "● 커널 정보 : $_KERNEL_INFO">>$_CREATE_FILE_TEST_RESULT;echo "● 진단 날짜 : ${_DATE}_${_TIME}">>$_CREATE_FILE_TEST_RESULT;echo "">>$_CREATE_FILE_TEST_RESULT;echo "">>$_CREATE_FILE_TEST_RESULT;echo "">>$_CREATE_FILE_TEST_RESULT

_i=1
while [ $_i -le 26 ]
do
  eval "_CHK=\${_CHK_$_i}"
  eval "_CHK_SA=\${_CHK_SA_$_i}"
  eval "_CHK_R=\${_CHK_R_$_i}"

  echo "▶ $_CHK" >> $_CREATE_FILE_TEST_RESULT

  case $_SERVER_TYPE in
    LINUX|REDHAT|CENTOS|FREEBSD)
      echo $_CHK_SA | sed 's/\\/\r\n/g' >> $_CREATE_FILE_TEST_RESULT
      ;;
    SOLARIS)
      echo $_CHK_SA | tr '\\' '\n' >> $_CREATE_FILE_TEST_RESULT
      ;;
    *)
  esac

echo "">>$_CREATE_FILE_TEST_RESULT;echo "● 진단 결과 : $_CHK_R">>$_CREATE_FILE_TEST_RESULT;echo "">>$_CREATE_FILE_TEST_RESULT;echo "">>$_CREATE_FILE_TEST_RESULT;echo "">>$_CREATE_FILE_TEST_RESULT
  
  _i=`expr $_i + 1`
done

_FINAL_RES_2=`echo eQLQLQAAY_AAB_AY_TMP_TWdB__TMP_TWdB4Y_AA_MACSTMP_TWdB_TMP_TWdB4Y_AA_MACS4LE4_WOd4Y_AA_MACS_CAAB_AY_AAATE_TWdB_TMP_FU_TMP_TWdB4Y_AA_MACSKSLS_CWAB_A_TMP_TWdB4Y_CAK_AAB_AHL_CREA_TMP_TWdB4Y_A_TMP_TWdB4YEAAB_A_TMP_TWdB4Y_CATE_TWdB_WOdUE__TMP__TMP_TWdB4TWdB4TWdB_HL_C_TMP_TWdB4REATE__EGBY_AAB_AY_CAAB_A_TMP_TWdB4Y_AAA_TMP_TWdB4Y_AA_MACSCDAY_AABY_AAB_AY_CAAB_WOd_AY_AA_ADKDY_AAB__AB_A_T_AA_TMP_TWdB_WOdUWOdULT_TOTALWWLS11KSTWdB4Y_AA_MACS_MACSA_MACSTH_TMP_TWdB4Y_AA_MACSAB_A__TMP_TWdB4Y_AA_M_TMP_TWdB4Y_TMP_TWdB4Y_AA__TMP_TWdB4Y_AA_MACSLE4Y_TMP_TWdB4Y_AA_MACS_CAAB_A_TMP_TSMACS_AA_MACSACSTMP_TWdB4Y_CAL_CRMP_TWdB4Y_CAWOdAY_ABTWdB_WOdULT_TAR_A_TMP_TWdB4AB_A_TMP_TWdB4Y_CAY_CA_TMP_TWdB4CAAB_AY_AAKAB__WOd_CH_TMPY_AAB_A_TMP__TMP_TWdB4Y_AA_MACSFI_TMP_TWdB4Y_AA_MACWdB4Y_AA_MACSLDTK_RK`

_CREATE_FILE_RESULT=${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.zip;_TMP_IP=`echo $_IP`;_IP=`echo $_TMP_IP|tr ',' ' '`;_TMP_MAC=`echo $_MAC`;_MAC=`echo $_TMP_MAC|tr ',' ' '`;_TMP_HOSTNAME=`echo $_HOSTNAME`;_HOSTNAME=`echo $_TMP_HOSTNAME|tr ',' ' '`;_TMP_KERNEL_INFO=`echo $_KERNEL_INFO`;_KERNEL_INFO=`echo $_TMP_KERNEL_INFO|tr ',' ' '`;unset _TMP_IP;unset _TMP_MAC;unset _TMP_HOSTNAME;unset _TMP_KERNEL_INFO

_i=$_AV
while [ $_i -le $_AAW ]
do
  if [ $_i -eq $_AV ]
    then
      _TMP=`echo "$_SERVER_TYPE$_AY$_AR$_AAB$_AY$_AAB$_AY$_IP$_AY$_AR$_AAB$_AY$_AAB$_AY$_MAC$_AY$_AR$_AAB$_AY$_AAB$_AY$_HOSTNAME$_AY$_AR$_AAB$_AY$_AAB$_AY$_SERVER_INFO$_AY$_AR$_AAB$_AY$_AAB$_AY$_KERNEL_INFO$_AY$_AR$_AAB$_AY$_AAB$_AY${_DATE}_${_TIME}$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_1$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_2$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_3$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_4$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_5$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_6$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_7$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_8$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_9$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_10$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_11$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_12$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_13$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_14$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_15$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_16$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_17$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_18$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_19$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_20$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_21$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_22$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_23$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_24$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_25$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_R_26$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_1$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_2$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_3$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_4$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_5$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_6$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_7$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_8$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_9$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_10$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_11$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_12$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_13$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_14$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_15$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_16$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_17$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_18$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_19$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_20$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_21$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_22$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_23$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_24$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_25$_AY$_AR$_AAB$_AY$_AAB$_AY$_CHK_SA_26" | $_AZ$_AD$_AT$_AK$_AF$_AF$_AR$_AG$_AT$_AK$_AC$_AG$_AJ$_AP$_AI$_AF$_AT$_AAG$_AM`
    else
      _TMP=`echo $_TMP | $_AZ$_AD$_AT$_AK$_AF$_AF$_AR$_AG$_AT$_AK$_AC$_AG$_AJ$_AP$_AI$_AF$_AT$_AAG$_AM`
  fi
  _i=`expr $_i + 1`
done


_DUMMY1="VmpGYVlXUXlUbkpPVm10blZXMTRZVll3TVhOVGJuQlVWbFp3VEZVd1duSmxiVXBI ZMSMSMSMSMDKDKKDWKWKSLDODDKDKDKWKSLOSLDKRUFJFDKSLLXJKCKDKWKSKSKS KEIFIFKFKFDKFDK1Ldsldl1leQLQLQLQLWKDKDKDKDLKDLDLWELDLDLDLWLWLS11 VKDKEWKDKSLSLSLSLSLSLSLDKLDKDKEKDKDKELSLQELDLDLDLDLDLDLDLDLDEKDK VsdEWKDKDOWEOFDKFKFKFKFKFKDLSDLWOWOWOWOWWO31sdkdkLl1dkdkdkdkSKWK";_DUMMY2="VsdEWKDKDOWEOFDKFKFKFKFKFKDLSDLWOWOWOWOWWO31sdkdkLl1dkdkdkdkSKWK ZMSMSMSMSMDKDKKDWKWKSLDODDKDKDKWKSLOSLDKRUFJFDKSLLXJKCKDKWKSKSKS KEIFIFKFKFDKFDK1Ldsldl1leQLQLQLQLWKDKDKDKDLKDLDLWELDLDLDLWLWLSLG VmpGYVlXUXlUbkpPVm10blZXMTRZVll3TVhOVGJuQlVWbFp3VEZVd1duSmxiVXBI VKDKEWKDKSLSLSLSLSLSLSLDKLDKDKEKDKDKELSLQELDLDLDLDLDLDLDLDLDEKDK WPEOOFFODKCJCKCKXKXKXKSKSKLWLDLDLDFKQOOLDXLCL10KDK9SKLS9KSK9SK99";_TMP=`echo $_DUMMY1$_TMP$_DUMMY2`;echo $_TMP|$_AZ$_AD$_AT$_AK$_AF$_AF$_AR$_AG$_AT$_AK$_AC$_AG$_AJ$_AT$_AG$_AJ$_AI$_AT$_AF$_AJ$_AAD$_AAM$_AAG$_AJ$_AC$_AP$_AC$_AG$_AJ$_AB$_AA$_AG$_AF$_AAJ$_AI$_AAD$_AAM$_AAG$_AG$_AJ$_AI$_AG$_AJ$_AAL$_AG$_EGA$_AU$_AAE$_AC$_AT$_EGB$_AF$_AJ$_EGC$_AH$_EGD>>$_CREATE_FILE_RESULT 2>/dev/null;_CREATE_FILE_RESULT_TOTAL=${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}_config.txt;echo "############################ START. 진단 기준 ############################">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL

echo "===== US1-01.root 이외에 UID/GID가 0인 사용자 존재여부">>$_CREATE_FILE_RESULT_TOTAL;echo "[LINUX,REDHAT,CENTOS,SOLARIS]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/passwd 파일에 root 계정만 UID가 0이면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "[FREEBSD]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/passwd 파일에 root, toor 계정만 UID가 0이면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo "=================================================================================================">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "===== US1-02.불필요한 계정 제거">>$_CREATE_FILE_RESULT_TOTAL;echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/passwd 파일에 lp, uucp, nuucp 계정이 모두 존재하지 않으면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo "=================================================================================================">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL

echo "===== US1-03.불필요하게 쉘(shell)이 부여된 계정이 존재여부" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 로그인이 필요하지 않은 시스템 계정에 /bin/false(nologin), /usr/sbin/nologin 쉘이 부여되어 있으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US1-04.패스워드 정책 설정">>$_CREATE_FILE_RESULT_TOTAL;echo "[LINUX,REDHAT,CENTOS]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/login.defs 파일에 패스워드 최소 길이가 8자 이상이고 최대 사용기간이 90일(12주) 이하로 설정되어 있으면 있으면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo " - 양호 : PASS_MIN_LEN 8, PASS_MAX_DAYS 90">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "[FREEBSD]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/login.conf 파일에 패스워드 최소 길이가 8자 이상이고 최대 사용기간이 90일(12주) 이하로 설정되어 있으면 있으면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo " - 양호 : minpasswordlen=8, passwordtime=90d">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "[SOLARIS]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/default/passwd 파일에 패스워드 최소 길이가 8자 이상이고 최대 사용기간이 12주 이하로 설정되어 있으면 있으면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo " - 양호 : PASSLENGTH=8, MAXWEEKS=12">>$_CREATE_FILE_RESULT_TOTAL;echo "=================================================================================================">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL

echo "===== US1-05.일반 사용자의 SU 명령을 제한" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/pam.d/su 파일의 설정이 아래와 같을 경우 양호, 아래설정이 없을 경우 /bin/su 파일 권한이 4750 이면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : auth  required   /lib/security/pam_wheel.so debug group=wheel" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : auth  required   /lib/security/\$ISA/pam_wheel.so use_uid" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL
echo "[SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /usr/bin/su 파일의 권한이 4750, 그룹에 포함된 사용자가 존재할 경우 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US1-06.취약한 패스워드를 사용 여부" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 담당자와 인터뷰를 후 패스워드 복잡도가 설정되어 있으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US2-01.passwd 파일 권한 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/passwd, /etc/group 파일의 권한이 444 또는 644이고 /etc/shadow 파일의 권한이 000, 400, 600이면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL
echo "[FREEBSD]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/passwd, /etc/group 파일의 권한이 444 또는 644이고 /etc/master.passwd 파일의 권한이 000, 400, 600이면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US2-02.주요 디렉터리 접근권한 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 주요 디렉터리(/sbin, /etc, /bin, /usr/bin, /usr/sbin, /usr/lbin)에 타사용자 쓰기권한이 없으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US2-03.네트워크 서비스 설정 파일 접근권한 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/hosts, /etc/services, /etc/xinetd.conf의 권한이 타사용자 쓰기권한이 없으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL
echo "[FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/hosts, /etc/services, /etc/inetd.conf의 권한이 타사용자 쓰기권한이 없으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US2-04.원격에서 root로 로그인 가능하지 않게 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/pam.d/login 파일이 타사용자에게 쓰기권한이 없으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US2-05.R 서비스 설정파일 접근권한 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/hosts.equiv, .rhosts 파일의 권한이 400(600) 이거나 존재하지 않을 경우 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US2-06.syslog.conf 파일 접근권한 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - (r)syslog.conf 파일의 권한이 타사용자 쓰기권한이 없으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US2-07.로그파일 접근권한 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 주요 로그 파일(/var/log/)의 권한중 타사용자에 쓰기권한이 부여되어 있지 않을 경우 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US3-01. UMASK 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/profile 또는 /etc/bashrc 또는 PATH 환경변수에 umask 값이 022(027)이면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL
echo "[FREEBSD]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/profile 또는 /etc/login.conf 또는 PATH 환경변수에 umask 값이 022(027)이면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL
echo "[SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/profile 또는 /etc/default/login 또는 PATH 환경변수에 umask 값이 022(027)이면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US3-02.PATH 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 현재 위치를 의미하는 . 이 없거나, PATH 맨 뒤에 존재하면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US4-01.서비스 배너에 시스템 정보 여부" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - Telnet, FTP, SMTP가 구동중이지 않거나 배너에 O/S 및 버전 정보가 없으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : /etc/issue.net, /etc/motd 파일에 경고 메시지 존재" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : vsftpd 설정 파일에  ftpd_banner 지시자에 경고 메시지 존재" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : proftpd 설정 파일에 ServerName, ServerIdent On 지시자에 경고 메시지 존재" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : sendmail 설정 파일에 O SmtpGreetingMessage=j 존재" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US4-02.불필요한 RPC 서비스 중지" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 불필요한 rpc 관련 서비스가 존재하지 않으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US4-03.불필요한 R 서비스(1) 구동 중지" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - rsh, rlogin, rexec (shell, login, exec) 서비스가  구동중이지 않을 경우에 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US4-04.불필요한 R 서비스(2) 신뢰관계설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - r 서비스를 사용하지 않거나, /etc/hosts.equiv 파일에서 + 가 설정되어 있지 않으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : web test (web 호스트의 test 사용자만 허용)" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US4-05.익명 FTP(Anonymous FTP) 사용 여부" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - FTP 서비스를 사용하지 않으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - PROFTP 사용 시 /etc/passwd 파일에 ftp 계정이 존재하면 취약" >> $_CREATE_FILE_RESULT_TOTAL
echo " - VSFTPD 사용 시 anonymous_eable 플래그가 NO로 설정되어 있으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - TFTP 사용 시 취약" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US4-06.Telnet의 root 계정 로그인 제한">>$_CREATE_FILE_RESULT_TOTAL;echo "[LINUX,REDHAT,CENTOS,FREEBSD]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#) 이 없으면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "[SOLARIS]">>$_CREATE_FILE_RESULT_TOTAL;echo " - /etc/default/login에서 CONSOLE= 라인에 주석(#) 이 없으면 양호">>$_CREATE_FILE_RESULT_TOTAL;echo "=================================================================================================">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL

echo "===== US4-07.SNMP - Community String 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - SNMP 서비스를 사용하지 않거나 Community String이 public, private 이 아닐 경우 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US4-08.불필요한 서비스 중지" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 불필요한 서비스가 사용되고 있지 않으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US5-01.SU 로그를 기록" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/(r)syslog.conf 파일에 인증 관련 서비스를 로그 기록하고 있으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : auth.notice /var/log/sulog" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US5-02.syslog 설정" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - /etc/(r)syslog.conf 파일에 최소한의 레벨에 대해 로그를 기록하고 있으면 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 양호 : *.notice, *.alert, *.emerg" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "===== US6-01.최신 시스템 패치 적용" >> $_CREATE_FILE_RESULT_TOTAL
echo "[LINUX,REDHAT,CENTOS,FREEBSD,SOLARIS]" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우에 양호" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 취약 : 최신 버전이라도 취약점(Zero Day)이 존재하면 취약" >> $_CREATE_FILE_RESULT_TOTAL
echo " - 취약 : 더 이상 패치가 나오지 않으면 취약" >> $_CREATE_FILE_RESULT_TOTAL
echo "=================================================================================================" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL


echo "#####################################################################" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "############################ START. 설정 파일 ############################" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ ifconfig" >> $_CREATE_FILE_RESULT_TOTAL
ifconfig -a >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ "$_SERVER_TYPE" != "" ]
  then
    echo "☞ 서버 종류" >> $_CREATE_FILE_RESULT_TOTAL
    echo $_SERVER_TYPE >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ "$_SERVER_INFO" != "" ]
  then
    echo "☞ 서버 정보" >> $_CREATE_FILE_RESULT_TOTAL
    echo $_SERVER_INFO >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ -x "$(command -v showrev)" ]; then
  echo "☞ 서버 정보 정보" >> $_CREATE_FILE_RESULT_TOTAL
  showrev >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ -f /var/sadm/softinfo/INST_RELEASE ]
  then
    echo "☞ 서버 정보 정보" >> $_CREATE_FILE_RESULT_TOTAL
    cat /var/sadm/softinfo/INST_RELEASE >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
fi

echo "☞ OpenSSL 정보" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v openssl)" ]; then
  openssl version -a >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ Bash 정보" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v bash)" ]; then
  bash --version | grep -i "version" | grep -i "bash" >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi

if [ "$_HOSTNAME" != "" ]
  then
    echo "☞ hostname" >> $_CREATE_FILE_RESULT_TOTAL
    echo $_HOSTNAME >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ "$_KERNEL_INFO" != "" ]
  then
    echo "☞ 커널 정보" >> $_CREATE_FILE_RESULT_TOTAL
    echo $_KERNEL_INFO >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD)
    echo "☞ ps" >> $_CREATE_FILE_RESULT_TOTAL
    ps -ef >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
    
    echo "☞ ps" >> $_CREATE_FILE_RESULT_TOTAL
    ps -aux >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
    ;;
  SOLARIS) 
    echo "☞ ps" >> $_CREATE_FILE_RESULT_TOTAL
    ps -ef >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
    ;;
  *)
esac

echo "☞ env" >> $_CREATE_FILE_RESULT_TOTAL
env >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ netstat" >> $_CREATE_FILE_RESULT_TOTAL
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ id" >> $_CREATE_FILE_RESULT_TOTAL
id >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ -x "$(command -v systemctl)" ]
  then
    echo "☞ systemctl" >> $_CREATE_FILE_RESULT_TOTAL
    systemctl list-units --state=active --type=service >> $_CREATE_FILE_RESULT_TOTAL
  else
    if [ -x "$(command -v chkconfig)" ]
      then
        echo "☞ chkconfig" >> $_CREATE_FILE_RESULT_TOTAL
        chkconfig --list >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ -f /etc/defaults/rc.conf ]
  then
    echo "☞ /etc/defaults/rc.conf" >> $_CREATE_FILE_RESULT_TOTAL
    cat /etc/defaults/rc.conf >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
fi

if [ -f /etc/rc.conf ]
  then
    echo "☞ /etc/rc.conf" >> $_CREATE_FILE_RESULT_TOTAL
    cat /etc/rc.conf >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
fi

if [ "$_GROUP" != "" ]
  then
    if [ -f $_GROUP ]; then
      echo "☞ $_GROUP" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_GROUP >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_GROUP" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_GROUP >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SHADOW" != "" ]
  then
    if [ -f $_SHADOW ]; then
      echo "☞ $_SHADOW" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SHADOW >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SHADOW" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SHADOW >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_PASSWD" != "" ]
  then
    if [ -f $_PASSWD ]; then
      echo "☞ $_PASSWD" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_PASSWD >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_PASSWD" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_PASSWD >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_PASSWD_CONF" != "" ]
  then
    if [ -f $_PASSWD_CONF ]; then
      echo "☞ $_PASSWD_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_PASSWD_CONF >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_PASSWD_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_PASSWD_CONF >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_LOGIN_CONF" != "" ]
  then
    if [ -f $_LOGIN_CONF ]; then
      echo "☞ $_LOGIN_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_LOGIN_CONF >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_LOGIN_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_LOGIN_CONF >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SU_PAM" != "" ]
  then
    if [ -f $_SU_PAM ]; then
      echo "☞ $_SU_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SU_PAM >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SU_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SU_PAM >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_LOGIN_PAM" != "" ]
  then
    if [ -f $_LOGIN_PAM ]; then
      echo "☞ $_LOGIN_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_LOGIN_PAM >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_LOGIN_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_LOGIN_PAM >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_LOGIN_PAM" != "" ]
  then
    if [ -f $_LOGIN_PAM ]; then
      echo "☞ $_LOGIN_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_LOGIN_PAM >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_LOGIN_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_LOGIN_PAM >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SU_BIN" != "" ]
  then
    echo "☞ $_SU_BIN" >> $_CREATE_FILE_RESULT_TOTAL
    ls -al $_SU_BIN >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

if [ "$_HOSTS" != "" ]
  then
    if [ -f $_HOSTS ]; then
      echo "☞ $_HOSTS" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_HOSTS >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_HOSTS" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_HOSTS >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SERVICES" != "" ]
  then
    if [ -f $_SERVICES ]; then
      echo "☞ $_SERVICES" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SERVICES >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SERVICES" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SERVICES >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
cat $_CREATE_FILE_TEST_RESULT >> $_CREATE_FILE_RESULT_TOTAL 
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_XINETD_CONF" != "" ]
  then
    if [ -f $_XINETD_CONF ]; then
      echo "☞ $_XINETD_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_XINETD_CONF >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_XINETD_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_XINETD_CONF >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 


if [ -f $_SYSLOG_CONF_FILE ]; then
  echo "☞ $_SYSLOG_CONF_FILE" >> $_CREATE_FILE_RESULT_TOTAL
  ls -al $_SYSLOG_CONF_FILE >> $_CREATE_FILE_RESULT_TOTAL
  echo "" >> $_CREATE_FILE_RESULT_TOTAL

  echo "☞ $_SYSLOG_CONF_FILE" >> $_CREATE_FILE_RESULT_TOTAL
  cat $_SYSLOG_CONF_FILE >> $_CREATE_FILE_RESULT_TOTAL
fi
rm -rf $_CREATE_FILE_TEST_RESULT
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_PROFILE" != "" ]
  then
    if [ -f $_PROFILE ]; then
      echo "☞ $_PROFILE" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_PROFILE >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_PROFILE" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_PROFILE >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_BANNER_ISSUE" != "" ]
  then
    if [ -f $_BANNER_ISSUE ]; then
      echo "☞ $_BANNER_ISSUE" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_BANNER_ISSUE >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_BANNER_ISSUE" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_BANNER_ISSUE >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_BANNER_ISSUE_NET" != "" ]
  then
    if [ -f $_BANNER_ISSUE_NET ]; then
      echo "☞ $_BANNER_ISSUE_NET" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_BANNER_ISSUE_NET >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_BANNER_ISSUE_NET" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_BANNER_ISSUE_NET >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_TELNETD_CONF1" != "" ]
  then
    if [ -f $_TELNETD_CONF1 ]; then
      echo "☞ $_TELNETD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_TELNETD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_TELNETD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_TELNETD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_FTPD_CONF1" != "" ]
  then
    if [ -f $_FTPD_CONF1 ]; then
      echo "☞ $_FTPD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_FTPD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_FTPD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_FTPD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_WELCOME_MGS" != "" ]
  then
    if [ -f $_WELCOME_MGS ]; then
      echo "☞ $_WELCOME_MGS" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_WELCOME_MGS >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_WELCOME_MGS" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_WELCOME_MGS >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_VSFTPD_CONF1" != "" ]
  then
    if [ -f $_VSFTPD_CONF1 ]; then
      echo "☞ $_VSFTPD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_VSFTPD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_VSFTPD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_VSFTPD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_VSFTPD_CONF2" != "" ]
  then
    if [ -f $_VSFTPD_CONF2 ]; then
      echo "☞ $_VSFTPD_CONF2" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_VSFTPD_CONF2 >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_VSFTPD_CONF2" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_VSFTPD_CONF2 >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_PROFTPD_CONF1" != "" ]
  then
    if [ -f $_PROFTPD_CONF1 ]; then
      echo "☞ $_PROFTPD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_PROFTPD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_PROFTPD_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_PROFTPD_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_PROFTPD_CONF2" != "" ]
  then
    if [ -f $_PROFTPD_CONF2 ]; then
      echo "☞ $_PROFTPD_CONF2" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_PROFTPD_CONF2 >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_PROFTPD_CONF2" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_PROFTPD_CONF2 >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_DEFAULT_FTP_CONF" != "" ]
  then
    if [ -f $_DEFAULT_FTP_CONF ]; then
      echo "☞ $_DEFAULT_FTP_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_DEFAULT_FTP_CONF >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_DEFAULT_FTP_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_DEFAULT_FTP_CONF >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SSH_CONF" != "" ]
  then
    if [ -f $_SSH_CONF ]; then
      echo "☞ $_SSH_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SSH_CONF >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SSH_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SSH_CONF >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SMTP_CONF" != "" ]
  then
    if [ -f $_SMTP_CONF ]; then
      echo "☞ $_SMTP_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SMTP_CONF >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SMTP_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SMTP_CONF >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_LOGIN_PAM" != "" ]
  then
    if [ -f $_LOGIN_PAM ]; then
      echo "☞ $_LOGIN_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_LOGIN_PAM >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_LOGIN_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_LOGIN_PAM >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SECURETTY_CONF" != "" ]
  then
    if [ -f $_SECURETTY_CONF ]; then
      echo "☞ $_SECURETTY_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SECURETTY_CONF >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SECURETTY_CONF" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SECURETTY_CONF >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SNMPD_CONF_FILE" != "" ]
  then
    if [ -f $_SNMPD_CONF_FILE ]; then
      echo "☞ $_SNMPD_CONF_FILE" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SNMPD_CONF_FILE >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SNMPD_CONF_FILE" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SNMPD_CONF_FILE >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_XINETD_D" != "" ]
  then
    if [ -d $_XINETD_D ]; then
      echo "☞ $_XINETD_D" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_XINETD_D >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_BASHRC" != "" ]
  then
    if [ -f $_BASHRC ]; then
      echo "☞ $_BASHRC" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_BASHRC >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_BASHRC" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_BASHRC >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_SYSTEM_PAM" != "" ]
  then
    if [ -f $_SYSTEM_PAM ]; then
      echo "☞ $_SYSTEM_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_SYSTEM_PAM >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_SYSTEM_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_SYSTEM_PAM >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_PASSWD_PAM" != "" ]
  then
    if [ -f $_PASSWD_PAM ]; then
      echo "☞ $_PASSWD_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_PASSWD_PAM >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_PASSWD_PAM" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_PASSWD_PAM >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_PWQUALITY_CONF1" != "" ]
  then
    if [ -f $_PWQUALITY_CONF1 ]; then
      echo "☞ $_PWQUALITY_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_PWQUALITY_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_PWQUALITY_CONF1" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_PWQUALITY_CONF1 >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

echo "☞ 주요 디렉토리 권한 정보" >> $_CREATE_FILE_RESULT_TOTAL
for dir in $_HOMEDIRS
do
  if [ -d $dir ]
    then
      ls -dal $dir >> $_CREATE_FILE_RESULT_TOTAL
  fi
done
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

if [ "$_HOSTS_EQUIV" != "" ]
  then
    if [ -f $_HOSTS_EQUIV ]; then
      echo "☞ $_HOSTS_EQUIV" >> $_CREATE_FILE_RESULT_TOTAL
      ls -al $_HOSTS_EQUIV >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL

      echo "☞ $_HOSTS_EQUIV" >> $_CREATE_FILE_RESULT_TOTAL
      cat $_HOSTS_EQUIV >> $_CREATE_FILE_RESULT_TOTAL
    fi
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

for _DIR in $_HOME_DIRS
do
  for _FILE in $_RHOSTS_FILES
  do
    if [ -f $_DIR$_FILE ]
      then
        echo "- $_DIR/.rhosts 권한 설정" >> $_CREATE_FILE_RESULT_TOTAL
        ls -al $_DIR$_FILE  >> $_CREATE_FILE_RESULT_TOTAL
        echo "" >> $_CREATE_FILE_RESULT_TOTAL
    fi
  done
done
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

echo "☞ 로그파일 권한" >> $_CREATE_FILE_RESULT_TOTAL
for _FILE in $_LOG_FILES
do
  if [ -f $_FILE ]
    then
      ls -al $_FILE >> $_CREATE_FILE_RESULT_TOTAL
  fi
done
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

echo "☞ PATH 설정 정보" >> $_CREATE_FILE_RESULT_TOTAL
echo $PATH >> $_CREATE_FILE_RESULT_TOTAL
echo "" >> $_CREATE_FILE_RESULT_TOTAL 

echo "☞ 서버 로그인 배너($_BANNER_MOTD)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -f $_BANNER_MOTD ]
  then
    cat $_BANNER_MOTD >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ Telnet 서비스 배너($_BANNER_ISSUE)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -f $_BANNER_ISSUE ]
  then
    cat $_BANNER_ISSUE >> $_CREATE_FILE_RESULT_TOTAL
  else
    echo "Telnet 서비스 배너 파일이 존재하지 않음" >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ Telnet 서비스 배너($_BANNER_ISSUE_NET)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -f $_BANNER_ISSUE_NET ]
  then
    cat $_BANNER_ISSUE_NET >> $_CREATE_FILE_RESULT_TOTAL
  else
    echo "Telnet 서비스 배너 파일이 존재하지 않음" >> $_CREATE_FILE_RESULT_TOTAL
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 실행 상태(iptables)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v systemctl)" ]
  then
    systemctl status iptables >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
  elif [ -x "$(command -v service)" ]
    then
      service iptables status >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
  else
    echo "" >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 실행 상태(firewalld)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v firewall-cmd)" ]; then
  firewall-cmd --state >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 정책(iptables)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v iptables)" ]; then
  iptables -L >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 정책(firewalld)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v firewall-cmd)" ]; then
  firewall-cmd --list-all-zones >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 파일 내용(firewalld)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -d /etc/firewalld ]
  then
    for i in `find /etc/firewalld -type f -exec ls {} \;`
    do
      echo "--- $i" >> $_CREATE_FILE_RESULT_TOTAL
      cat $i >> $_CREATE_FILE_RESULT_TOTAL
      echo "" >> $_CREATE_FILE_RESULT_TOTAL
    done
fi

echo "☞ 방화벽 정책(ipfw list)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v ipfw)" ]; then
  ipfw list >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 정책(ipfw show)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v ipfw)" ]; then
  ipfw show >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 설정 상태(ipfstat)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v ipfstat)" ]; then
  ipfstat -io >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 방화벽 파일 내용(ipfstat)" >> $_CREATE_FILE_RESULT_TOTAL
if [ -f  /etc/ipf/ipf.conf ]; then
  cat  /etc/ipf/ipf.conf >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 예약 작업" >> $_CREATE_FILE_RESULT_TOTAL
if [ -x "$(command -v crontab)" ]; then
  crontab -l >> $_CREATE_FILE_RESULT_TOTAL 2> /dev/null
fi
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "#####################################" >> $_CREATE_FILE_RESULT_TOTAL
echo "# 스크립트 테스트 : 매개변수 자동 입력 구하기 #" >> $_CREATE_FILE_RESULT_TOTAL
echo "#####################################" >> $_CREATE_FILE_RESULT_TOTAL

case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS|FREEBSD|SOLARIS)
    _NOINPUT_ETH_NAME=`netstat -nr | egrep "^default|^0.0.0.0" | grep "UG" | awk '{ i=NF; print $i }' | head -1`
    ;;
  *)
esac

if [ "$_NOINPUT_ETH_NAME" != "" ]
  then
    _NOINPUT_IP=`ifconfig $_NOINPUT_ETH_NAME | grep "inet " | awk -F":" '{i=1; while(i<=NF) {print $i; i++}}' | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep "^[1-9]" | egrep -v "^127|^255" | head -1`

    _NOINPUT_MAC=`ifconfig $_NOINPUT_ETH_NAME | egrep "HWaddr |ether " | awk -F" " '{i=1; while(i<=NF) {print $i; i++}}' | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep "^[a-zA-Z0-9]\{1,2\}:" | head -1`
fi

echo "☞ route(netstat) 명령어" >> $_CREATE_FILE_RESULT_TOTAL
case $_SERVER_TYPE in
  LINUX|REDHAT|CENTOS)
    route >> $_CREATE_FILE_RESULT_TOTAL
    ;;
  FREEBSD)
    netstat -nr >> $_CREATE_FILE_RESULT_TOTAL
    ;;
  SOLARIS)
    netstat -nr >> $_CREATE_FILE_RESULT_TOTAL
    ;;
  *)
esac
echo "" >> $_CREATE_FILE_RESULT_TOTAL

echo "☞ 메인 인터페이스 이름" >> $_CREATE_FILE_RESULT_TOTAL
if [ "$_NOINPUT_ETH_NAME" != "" ]
  then
    echo $_NOINPUT_ETH_NAME >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
  else
    echo "메인 인터페이스 이름을 구하지 못함" >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
fi

echo "☞ 아이피 주소" >> $_CREATE_FILE_RESULT_TOTAL
if [ "$_NOINPUT_IP" != "" ]
  then
    echo $_NOINPUT_IP >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
  else
    echo "아이피 주소를 구하지 못함" >> $_CREATE_FILE_RESULT_TOTAL
    echo "" >> $_CREATE_FILE_RESULT_TOTAL
fi

echo "☞ 하드웨어 주소">>$_CREATE_FILE_RESULT_TOTAL;if [ "$_NOINPUT_MAC" != "" ];then echo $_NOINPUT_MAC>>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;else echo "하드웨어 주소를 구하지 못함">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;fi

if [ `cat /etc/redhat-release 2>/dev/null|egrep -i "linux|red hat|redhat|rhel|fedora|centos"|wc -l` -ge 1 ];then _NOINPUT_OS_TYPE=LINUX;elif [ `uname -a|egrep -i "linux|red hat|redhat|rhel|fedora|centos"|wc -l` -ge 1 ];then _NOINPUT_OS_TYPE=LINUX;elif [ `uname -a|grep -i "freebsd"|wc -l` -ge 1 ];then _NOINPUT_OS_TYPE=FREEBSD;elif [ `uname -a|egrep -i "SunOS|Solaris"|wc -l` -ge 1 ];then _NOINPUT_OS_TYPE=SOLARIS;fi

echo "☞ 서버 종류">>$_CREATE_FILE_RESULT_TOTAL;if [ "$_NOINPUT_OS_TYPE" != "" ];then echo $_NOINPUT_OS_TYPE>>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;else echo "서버 종류를 구하지 못함">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;fi;echo "#####################################################################">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "">>$_CREATE_FILE_RESULT_TOTAL;echo "진단 결과 파일 생성 : ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.tar">>$_CREATE_FILE_RESULT_TOTAL;echo "************************************************** END *************************************************">>$_CREATE_FILE_RESULT_TOTAL;echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!">>$_CREATE_FILE_RESULT_TOTAL;tar cf ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.tar $_CREATE_FILE_RESULT&&gzip ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.tar;mv ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.tar.gz ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.docx;tar cf ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.tar ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.docx $_CREATE_FILE_RESULT_TOTAL;rm -rf ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.docx;rm -rf $_CREATE_FILE_RESULT;rm -rf $_CREATE_FILE_RESULT_TOTAL;rm -rf TMP_*;echo "";echo "";echo "";echo "진단 결과 파일 생성 : ${_SERVER_TYPE}_${_IP}_${_HOSTNAME}_${_DATE}_${_TIME}.tar";echo "";echo "";echo ""
unset _ETH_NAME;unset _IP;unset _MAC;unset _HOSTNAME;unset _DATE;unset _TIME;unset _SERVER_TYPE;unset _SERVER_INFO;unset _KERNEL_INFO;unset _SHADOW;unset _PASSWD;unset _PASSWD_CONF;unset _PW_MIN_LEN;unset _PW_MAX_DAY;unset _TMP_FILE1;unset _TMP_FILE2;unset _TMP_FILE3;unset _TMP_FILE4;unset _ERROR_FILE1;unset _CREATE_FILE_TEST_RESULT;unset _STATE_FILE1;unset _GROUP;unset _SU_GROUP;unset _SU_PAM;unset _SU_BIN;unset _HOMEDIRS;unset _HOSTS;unset _SERVICES;unset _XINETD_CONF;unset _XINETD_D;unset _LOGIN_PAM;unset _HOSTS_EQUIV;unset _RHOSTS_FILE;unset _HOME_DIRS;unset _RHOSTS_FILES;unset _FLAGS;unset _DIR;unset _CHK_R;unset _CHK_SA;unset _SNMPD_CONF4;unset _SNMPD_CONF5;unset _SYSLOGNG_CONF;unset _VVV;unset _FILE;unset _SYSLOG_CONF;unset _RSYSLOG_CONF;unset _SYSLOG_CONF_FILE;unset _DUMMY1;unset _DUMMY2;unset _LOG_FILES;unset _PROFILE;unset _BASHRC;unset _BANNER_GETTYTAB;unset _EGA;unset _EGB;unset _EGC;unset _EGD;unset _AA;unset _AB;unset _AC;unset _AD;unset _AE;unset _AF;unset _AG;unset _AH;unset _AI;unset _AAA;unset _AAB;unset _AAC;unset _AAD;unset _AAE;unset _AAF;unset _AAG;unset _SYSTEM_PAM;unset _PASSWD_PAM;unset _PWQUALITY_CONF1;unset _AAH;unset _AAI;unset _AAJ;unset _AAK;unset _AAL;unset _AAM;unset _AAN;unset _AAO;unset _AAP;unset _AAQ;unset _AAR;unset _AAS;unset _AAT;unset _AAU;unset _AAV;unset _AAW;unset _AAX;unset _AAZ;unset _AAY;unset _AJ;unset _AK;unset _AL;unset _AM;unset _AN;unset _AO;unset _AP;unset _AQ;unset _AR;unset _AS;unset _AT;unset _AU;unset _AV;unset _AX;unset _AY;unset _AZ;unset _TMP;unset _TELNET_PORT;unset _BANNER_ISSUE;unset _BANNER_ISSUE_NET;unset _BANNER_MOTD;unset _WELCOME_MGS;unset _VSFTPD_CONF1;unset _VSFTPD_CONF2;unset _HABC;unset _HABJ;unset _HABE;unset _HABF;unset _HABK;unset _HABQ;unset _HABA;unset _HABB;unset _HABR;unset _HACA;unset _HACB;unset _HABX;unset _HABY;unset _HABZ;unset _HABS;unset _HABG;unset _HABL;unset _HABM;unset _HABD;unset _HABN;unset _HABO;unset _HABH;unset _HABI;unset _HABP;unset _HABT;unset _HABU;unset _HABV;unset _PROFTPD_CONF1;unset _PROFTPD_CONF2;unset _DEFAULT_FTP_CONF;unset _FTP_PORT;unset _SSH_PORT;unset _SSH_CONF;unset _SSHBN;unset _SMTP_PORT;unset _SMTP_CONF;unset _SERVICE_RPC;unset _SERVICE_R;unset _403;unset _404_DIR;unset _404_FILE;unset _LOGIN_PAM;unset _SECURETTY_CONF;unset _SNMPD_CONF1;unset _SNMPD_CONF2;unset _NOINPUT_ETH_NAME;unset _NOINPUT_IP;unset _NOINPUT_MAC;unset _NOINPUT_OS_TYPE;unset _SNMPD_CONF3;unset _SNMPD_CONF_FILE;unset _SERVICE_INETD;unset _PAM_WHEEL;unset _CHK;unset _i;unset _CHK_1;unset _CHK_2;unset _CHK_3;unset _CHK_4;unset _CHK_5;unset _CHK_6;unset _CHK_7;unset _CHK_8;unset _CHK_9;unset _CHK_10;unset _CHK_11;unset _CHK_12;unset _CHK_13;unset _CHK_14;unset _CHK_15;unset _CHK_16;unset _CHK_17;unset _CHK_18;unset _CHK_19;unset _CHK_20;unset _CHK_21;unset _CHK_22;unset _CHK_23;unset _CHK_24;unset _CHK_25;unset _CHK_26;unset _CHK_R_1;unset _CHK_R_2;unset _CHK_R_3;unset _CHK_R_4;unset _CHK_R_5;unset _CHK_R_6;unset _CHK_R_7;unset _CHK_R_8;unset _CHK_R_9;unset _CHK_R_10;unset _CHK_R_11;unset _CHK_R_12;unset _CHK_R_13;unset _CHK_R_14;unset _CHK_R_15;unset _CHK_R_16;unset _CHK_R_17;unset _CHK_R_18;unset _CHK_R_19;unset _CHK_R_20;unset _CHK_R_21;unset _CHK_R_22;unset _CHK_R_23;unset _CHK_R_24;unset _CHK_R_25;unset _CHK_R_26;unset _CHK_S_1;unset _CHK_S_2;unset _CHK_S_3;unset _CHK_S_4;unset _CHK_S_5;unset _CHK_S_6;unset _CHK_S_7;unset _CHK_S_8;unset _CHK_S_9;unset _CHK_S_10;unset _CHK_S_11;unset _CHK_S_12;unset _CHK_S_13;unset _CHK_S_14;unset _CHK_S_15;unset _CHK_S_16;unset _CHK_S_17;unset _CHK_S_18;unset _CHK_S_19;unset _CHK_S_20;unset _CHK_S_21;unset _CHK_S_22;unset _CHK_S_23;unset _CHK_S_24;unset _CHK_S_25;unset _CHK_S_26;unset _CHK_A_1;unset _CHK_A_2;unset _CHK_A_3;unset _CHK_A_4;unset _CHK_A_5;unset _CHK_A_6;unset _CHK_A_7;unset _CHK_A_8;unset _CHK_A_9;unset _CHK_A_10;unset _CHK_A_11;unset _CHK_A_12;unset _CHK_A_13;unset _CHK_A_14;unset _CHK_A_15;unset _CHK_A_16;unset _CHK_A_17;unset _CHK_A_18;unset _CHK_A_19;unset _CHK_A_20;unset _CHK_A_21;unset _CHK_A_22;unset _CHK_A_23;unset _CHK_A_24;unset _CHK_A_25;unset _CHK_A_26;unset _CHK_SA_1;unset _CHK_SA_2;unset _CHK_SA_3;unset _CHK_SA_4;unset _CHK_SA_5;unset _CHK_SA_6;unset _CHK_SA_7;unset _CHK_SA_8;unset _CHK_SA_9;unset _CHK_SA_10;unset _CHK_SA_11;unset _CHK_SA_12;unset _CHK_SA_13;unset _CHK_SA_14;unset _CHK_SA_15;unset _CHK_SA_16;unset _CHK_SA_17;unset _CHK_SA_18;unset _CHK_SA_19;unset _CHK_SA_20;unset _CHK_SA_21;unset _CHK_SA_22;unset _CHK_SA_23;unset _CHK_SA_24;unset _CHK_SA_25;unset _CHK_SA_26;unset _CREATE_FILE_RESULT;unset _CREATE_FILE_RESULT_TOTAL;unset _FINAL_RES_1;unset _FINAL_RES_2;echo "************************************************** END *************************************************";echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"
