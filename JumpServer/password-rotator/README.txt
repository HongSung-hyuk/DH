JumpServer 등록 자산의 Linux 로컬 비밀번호 갱신

JumpServer API에서 지정한 자산과 활성 SSH 키 계정을 조회하고, RSA 키로 대상
Linux에 직접 SSH 접속한다. 지정한 로컬 계정의 비밀번호 만료일 하루 전부터 또는
다음 로그인 때 변경하도록 설정되어 있으면 새 32자 비밀번호를 생성한다. 대상
서버의 UTC 날짜와 /etc/shadow 기준으로 판단한다. 계정 만료, 계정 비활성 기간
초과, 잠금, 빈 비밀번호, root, LDAP/AD 계정은 갱신 대상에서 제외한다.

이 구성은 대상 OS의 비밀번호를 관리한다. 승인된 JumpServer Password 계정에
password_account_id를 지정하면 Linux 갱신 직후 해당 계정에 API로 동기화한다.
이 설정에는 지정 API 키와 자산·계정에만 쓰기를 허용하는 JumpServer Core 확장이
필요하다. 비밀번호는 TLS 연결의 서명된 요청 본문으로 전송하며 응답에는 포함하지 않는다.
동기화가 실패하면 암호화된 값을 보관하고 다음 주기에 API 동기화만 재시도한다.
자동 접속에 사용할 SSH 키 계정과 갱신 대상 계정은 같은 사용자로 지정할 수 있으나,
대상 계정의 비밀번호 만료로 SSH 명령이 거부될 수 있다. 예제는 별도 RSA 서비스
계정(rotator)으로 접속해 관리 계정(maintenance)을 갱신한다.

1. JumpServer와 대상 Linux 준비

   대상 Linux를 JumpServer 자산으로 등록하고, 해당 자산에서 사용할 전용 RSA
   키의 접속 계정을 SSH Key 타입으로 등록한다. RSA 공개키를 대상 서버의 해당
   계정 authorized_keys에 추가한다. 가능한 경우 공개키 항목의 from=으로 갱신
   컨테이너의 실제 출발지 IP를 제한한다. 무인 실행은 패스프레이즈 없는 전용 키가
   필요하다. 이 키의 사용처를 제한하고 갱신 서버의 secrets에만 운영 사본을 둔다.

   JumpServer API용으로 자산 보기와 계정 메타데이터 보기 권한을 가진 전용 사용자의
   Access Key를 만든다. 계정 비밀 조회 및 쓰기 권한은 필요 없다. 계정 및 자산 UUID,
   조직 UUID, 자산에 적힌 주소와 실제 SSH 포트를 기록한다. 설치한 버전의 /api/docs/
   에서 /api/v1/assets/assets/{id}/와 /api/v1/accounts/accounts/{id}/를 확인한다.
   API는 HTTPS로 연결하며 SSH는 등록 자산 주소로 직접 연결한다. 컨테이너에서
   JumpServer HTTPS와 자산 SSH에 도달할 수 있어야 한다.

   대상 서버의 root 셸에서 제공된 jms-password-rotate 파일을 설치한다. Rocky Linux
   계열의 Bash, sudo, getent, flock, chpasswd가 필요하며 대상 계정은 로컬 계정이어야 한다.

     install -o root -g root -m 0755 jms-password-rotate /usr/local/sbin/jms-password-rotate
     restorecon -v /usr/local/sbin/jms-password-rotate
     visudo -f /etc/sudoers.d/jms-password-rotate

   아래 예시의 rotator와 maintenance를 각각 실제 SSH 로그인 및 갱신 사용자로 바꾼다.
   서버별로 지정된 사용자에 대한 명령과 인자만 허용한다. 와일드카드는 사용하지
   않는다. sudo가 stdin 비밀번호를 기록하지 않도록 I/O 로깅 설정을 확인한다.

     rotator ALL=(root) NOPASSWD: NOLOG_INPUT: NOLOG_OUTPUT: /usr/local/sbin/jms-password-rotate status maintenance, /usr/local/sbin/jms-password-rotate apply maintenance

   즉시 변경 시험이 필요한 계정에만 동일한 인자로 force 명령을 추가한다.
   계정 자동 등록을 사용할 때는 동일한 인자로 discover 명령을 추가한다.

     chmod 0440 /etc/sudoers.d/jms-password-rotate
     visudo -c

   sudoers의 requiretty를 적용하는 환경에서는 해당 명령이 비대화형으로 실행되도록
   명령 범위에서 정책을 검토한다. SSH/Sudo 세션 기록 제품을 별도로 사용한다면
   stdin 평문이 기록되지 않도록 이 작업의 정책을 확인한다.

   기존 ansible 계정 재사용 예시

   target_server에서 SSH 접속 계정은 ansible, 비밀번호 변경 대상은 test로 지정한다.
   기존 Ansible 키와 별개로 이 서버의 갱신용 RSA 키를 사용한다. ansible의 기존 키
   항목을 보존하고, 갱신용 공개키 한 줄에만 아래 옵션을 붙인다. IP는 갱신 컨테이너의
   실제 출발지와 일치해야 한다.

     from="192.0.2.10",restrict,command="/usr/local/sbin/jms-rotation-command" ssh-rsa <갱신용_공개키>

   아래 내용을 /usr/local/sbin/jms-rotation-command에 root:root, 모드 0755로
   설치한다. 허용된 전체 명령 문자열을 대조하고, 선택된 모드만 sudo에 전달한다.

     #!/bin/bash
     case "${SSH_ORIGINAL_COMMAND:-}" in
       'sudo -n /usr/local/sbin/jms-password-rotate status test') mode=status ;;
       'sudo -n /usr/local/sbin/jms-password-rotate apply test') mode=apply ;;
       'sudo -n /usr/local/sbin/jms-password-rotate force test') mode=force ;;
       'sudo -n /usr/local/sbin/jms-password-rotate discover test') mode=discover ;;
       *) exit 126 ;;
     esac
     exec /usr/bin/sudo -n /usr/local/sbin/jms-password-rotate "$mode" test

   sudoers 예시의 로그인 계정을 ansible, 대상 계정을 test로 지정한다. 자동 탐색이
   필요한 자산은 discover test를 추가한다. 즉시 갱신 시험에만 force test를 허용하고,
   완료 후 force를 SSH 명령 검사 목록과 sudoers 규칙에서 제거한다. 갱신용 키로
   status test는 동작하고, 대화형 셸과 다른 계정 대상 명령은 거부되는지 확인한다.

2. Rocky Linux JumpServer 호스트에 Compose 배치

   이 디렉터리를 /opt/password-rotator에 복사하고 root 셸에서 준비한다. 아래 UID/GID는
   Compose의 컨테이너 사용자와 일치한다. Docker userns-remap을 사용한다면 실제 호스트
   UID/GID 매핑에 맞춰 권한을 조정한다. 각 파일은 LF 줄바꿈으로 배치한다.

     cd /opt/password-rotator
     umask 077
     install -d -o root -g 10001 -m 0750 config secrets
     install -d -o 10001 -g 10001 -m 0700 state
     install -m 0640 -o root -g 10001 settings.example.json config/settings.json
     vi config/settings.json

   targets에 허용할 자산과 계정을 지정한다. 대상별 id는 서로 달라야 하며 기존 id를
   다른 자산/주소/포트/계정에 재사용하지 않는다. 변환 없이 JumpServer 자산 주소와
   일치하는 IP 또는 DNS 이름을 사용한다. SSH private key 파일명은 rsa_key_file에,
   포트는 port에 기재한다. 최초 배포에서는 apply를 false로 유지한다.

   discover_shell_accounts를 true로 설정한 자산에서 일반 로컬 셸 계정을 찾는다.
   /etc/login.defs의 일반 사용자 UID 범위와 /etc/shells를 기준으로 하며 root,
   시스템 계정, 디렉터리 계정, nologin 및 false는 제외한다. JumpServer API 키에
   계정 추가 권한을 부여한 뒤 apply를 true로 하면 등록되지 않은 사용자 이름만
   비활성 계정으로 추가한다. 비밀번호는 빈 상태로 저장하고 비고에 등록 당시 상태를
   표시한다. 기존 계정과 권한은 그대로 유지한다. 자동 발견은 비밀번호 갱신 대상
   목록을 변경하지 않는다.

   검증된 SSH 호스트 공개키를 config/known_hosts에 작성한다. 기본 포트는 hostname,
   비기본 포트는 [hostname]:port 형식이다. IP 등록이면 같은 IP를 사용한다. 관리 콘솔
   또는 등록 기록으로 SSH 호스트 키 지문을 대조한다. 사내 CA를 쓰면 검증된 CA PEM을
   config/jumpserver-ca.pem에 둔다.

     chown root:10001 config/known_hosts
     chmod 0640 config/known_hosts

   사내 CA 파일에도 동일한 소유권과 권한을 적용한다. 승인된 관리자만 읽을 수 있는
   파일에서 JumpServer Access Key ID와 Secret을 각각 복사한다. 예제 원본 경로는
   실제 비밀 파일 경로로 바꾼다. 값 자체를 명령행이나 로그에 남기지 않는다.

     install -m 0400 -o 10001 -g 10001 /root/rotation-input/jms_access_key_id secrets/jms_access_key_id
     install -m 0400 -o 10001 -g 10001 /root/rotation-input/jms_access_key_secret secrets/jms_access_key_secret
     install -m 0400 -o 10001 -g 10001 /root/rotation-input/linux01_rsa secrets/linux01_rsa

   다음 명령은 최초 한 번만 실행한다. 기존 vault.key를 바꾸면 이전 암호문을 읽을
   수 없다. 파일이 정상 생성됐는지 확인하고 별도의 승인된 비밀 저장소에 백업한다.

     (umask 077; set -o noclobber -o pipefail; openssl rand -base64 32 | tr '+/' '-_' > secrets/vault.key)
     chown 10001:10001 secrets/vault.key
     chmod 0400 secrets/vault.key

3. 읽기 전용 확인과 배포

     docker compose config -q
     docker compose build --pull
     docker compose run --rm --no-deps rotator run --once

   --once는 apply 값과 관계없이 검사만 수행한다. DUE는 갱신 시점 도달, NOT_DUE는
   아직 유효함, NO_EXPIRY는 비밀번호 만료 기한 없음, INELIGIBLE은 정책상 갱신 대상이
   될 수 없음을 뜻한다. 종료 코드 1이면 API 응답, UID/파일 권한, SSH known_hosts,
   SSH 경로 및 대상 sudo 명령을 점검한다. 계정 자동 등록이 켜져 있으면 미등록
   셸 계정을 UNREGISTERED_SHELL_ACCOUNT로 출력한다.

   아래 명령은 apply 값과 관계없이 지정한 시험 계정 하나의 비밀번호를 만료일을
   기다리지 않고 변경한다. 대상에서 해당 계정의 force 명령을 허용해야 하며 잠금,
   최소 변경 간격 등 계정 정책은 적용된다. CHANGED가 나오면 chage -l로 확인한다.

     docker compose run --rm --no-deps rotator rotate-now linux01-maintenance

   운영을 시작하려면 config/settings.json에서 apply를 true로 저장한다. 시작 즉시
   검사하며 이후 interval_seconds마다 반복한다. 자동 등록 성공 건은 로그에
   REGISTERED_NO_PASSWORD로 표시된다.

     docker compose up -d rotator
     docker compose logs --tail 50 rotator
     docker compose run --rm --no-deps rotator run --once

   운영 대상은 사전 확인이 끝난 뒤 추가한다. 설정을 편집하면 docker compose restart
   rotator로 재로딩한다. 해당 호스트에서 이 Compose 프로젝트를 한 인스턴스만 운영한다.

4. 결과 조회와 미확정 변경 복구

   비밀번호는 state/rotations.sqlite3에 Fernet 암호문으로 저장된다. 별도로 보관한
   vault.key로 복호화한다. 상태 파일을 백업할 때에는 먼저 서비스를 멈춘다. 상태와
   키 모두에 접근할 수 있는 사용자, Docker 관리자 및 단말 기록의 접근 범위를 제한한다.

     docker compose run --rm --no-deps rotator status
     docker compose run --rm --no-deps rotator show linux01-maintenance

   show는 인터랙티브 터미널에 평문을 표시하므로 녹화·공유 중인 단말에서 실행하지
   않는다. 키와 상태 DB를 함께 유실하면 대상 시스템의 승인된 복구 절차를 사용한다.

   SSH 연결 단절, PAM 실패 또는 프로세스 종료로 갱신 성공 여부가 불명확하면 해당
   대상의 재시도를 보류하고 PENDING으로 기록한다. 다른 대상의 검사는 계속된다.
   아래 명령으로 후보 비밀번호를 조회하고 승인된 관리 경로에서 실제 적용 여부를
   확인한다. 패스워드 SSH를 켜거나 반복 로그인해 확인할 필요는 없다. 적용 여부를
   확인할 수 없으면 PENDING을 유지하고 관리자 복구 절차로 대조한다.

     docker compose run --rm --no-deps rotator show linux01-maintenance --pending

   후보가 실제 적용된 경우에만 다음 명령으로 확정한다.

     docker compose run --rm --no-deps rotator resolve linux01-maintenance changed

   변경이 일어나지 않았음을 확인한 경우 다음 명령으로 보류를 해제한다. 다음 검사에서
   여전히 만료 상태인 경우에만 다시 시도한다.

     docker compose run --rm --no-deps rotator resolve linux01-maintenance unchanged

공식 참조
  JumpServer API 인증  https://www.jumpserver.com/blog/jumpserver-api-authentication-guide
  JumpServer REST API  https://www.jumpserver.com/docs/developer-guide/rest-api
  Linux shadow 필드   https://www.man7.org/linux/man-pages/man5/shadow.5.html
