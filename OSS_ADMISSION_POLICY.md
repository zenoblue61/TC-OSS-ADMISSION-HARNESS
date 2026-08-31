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
