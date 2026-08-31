# OSS Admission Policy v1

## 승인 규칙

1. 모든 외부 소스는 registry record와 evidence를 가져야 한다.
2. Git 소스는 40자리 소문자 SHA로 고정한다. 태그·브랜치·`latest`는 불허한다.
3. 패키지 소스는 정확한 SemVer 또는 digest로 고정한다. 범위(`^`, `~`, `>`, `*`)는 불허한다.
4. 허용 라이선스는 `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `MPL-2.0`이다.
5. `GPL-*`, `AGPL-*`, `LGPL-*`, `SSPL-*`, `BUSL-*`, `LicenseRef-*`, `NOASSERTION`은 명시적 예외가 없는 한 차단한다.
6. 승인은 사용 목적과 대상 시스템에 한정된다. 목적 변경은 재승인 대상이다.
7. 180일이 지난 승인은 만료로 판정한다.

## 예외

예외는 `exception_approval`에 승인자, 근거, 만료일을 함께 기록해야 하며 만료된 예외는 차단한다.

## 상태 전이

`PENDING → APPROVED → REVOKED` 또는 `PENDING → BLOCKED`. 자동으로 `APPROVED`가 되는 전이는 없다.

## 발견 (Discovery)

8. 발견은 읽기 전용이다. 네트워크 접근, 의존성 설치, lockfile·manifest·레지스트리 수정은 금지한다.
9. 발견기는 `ADMITTED_MATCH`, `PENDING_ADMISSION`, `UNPINNED_BLOCKED` 세 상태만 산출한다.
   `APPROVED`를 생성하거나 레지스트리에 기록을 추가하지 않는다.
10. 대조는 `source_url + immutable_ref` 두 필드로만 수행한다. 패키지 이름, 라이선스, 컴포넌트 이름은
    일치 판정 근거가 될 수 없다.
11. `APPROVED` record만 `ADMITTED_MATCH`를 만든다. `PENDING`, `BLOCKED`, `REVOKED` record는
    ref가 같아도 일치로 보지 않는다.
12. 고정되지 않은 ref(버전 범위, branch, tag, `latest`, 무제약)는 레지스트리 대조 **이전에**
    `UNPINNED_BLOCKED`로 판정한다. 불변으로 인정하는 ref는 40자리 commit SHA, 정확한 버전, digest뿐이다.
13. 입력이 없거나 손상되면 fail-closed로 처리한다. 발견 결과는 `scan_status: FAIL`이 되고 종료 코드는
    1이며, 레지스트리를 읽을 수 없으면 어떤 후보도 승인 일치로 판정하지 않는다.
14. 발견 결과는 타임스탬프·절대 경로 없이 정렬되어 재현 가능해야 한다. 동일한 입력은 동일한 바이트를
    산출한다.

### 발견 후 처리

`PENDING_ADMISSION` 또는 `UNPINNED_BLOCKED` 후보는 사람이 심사한다. 승인하려면 먼저 소스를 불변
ref로 고정한 뒤, registry record와 evidence를 추가하고 P0~P2 validator를 통과시켜야 한다. 발견기가
후보를 보고했다는 사실 자체는 어떤 승인 근거도 되지 않는다.
