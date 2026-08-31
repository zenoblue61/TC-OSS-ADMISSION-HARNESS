# TC-OSS-ADMISSION-HARNESS

외부 오픈소스·GitHub 소스를 제품에 반입하기 전에 **특정 소스·특정 불변 버전·특정 사용 목적**을 승인하고 CI에서 검증하는 공급망 거버넌스 Harness입니다.

## 안전 모델

- `registry/oss-registry.json`에 없는 외부 소스는 허용하지 않습니다.
- 승인 단위는 패키지 이름이 아닌 `source_url + immutable_ref`입니다.
- `immutable_ref`는 Git commit SHA(40자리) 또는 정확한 버전 고정이어야 합니다.
- `APPROVED` 항목만 통과합니다. `PENDING`, `BLOCKED`, `REVOKED`는 CI를 실패시킵니다.
- 라이선스, 사용 목적, 소유자, 검토일, 증거 파일을 빠뜨릴 수 없습니다.

## 실행

```bash
python3 scripts/validate_admissions.py
python3 -m unittest discover -s tests -v
```

검증기는 표준 라이브러리만 사용합니다. 소스 코드·lockfile을 자동 설치하거나 변경하지 않습니다.

## TC-JARVIS 연결

각 승인 record의 `jarvis_ledger`는 TC-JARVIS master ledger에서 추적할 식별자와 상태를 담습니다. CI 결과는 `evidence/validation-result.json`에 생성하며, 이 파일을 상위 레저의 evidence reference로 연결할 수 있습니다.

## 초기 범위

P0~P2: admission contract, 레지스트리/정책 검증, GitHub Actions gate. CVE 데이터베이스 연동과 자동 의존성 업데이트는 의도적으로 범위 밖입니다.
